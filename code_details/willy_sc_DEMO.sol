// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract WillyVault {
    // Types

    /// @notice The four phases of the vault.
    /// @dev Opening is informational: competing proposals and holder actions remain possible.
    ///      Active/Opening -> Window -> Finalized. `cancel()` invalidates the cycle and returns to Active.
    enum Phase {
        Active, // everyday use: the holder can update the plan and withdraw
        Opening, // proposals collecting approvals; does NOT lock holder actions or other proposals
        Window, // quorum reached: the veto window is running
        Finalized // shares are fixed: beneficiaries can claim
    }

    /// @notice The role under which a signer approved the opening (used in events).
    enum SignerRole {
        Designee,
        Notary,
        NotarySub
    }

    // Events

    event Deposited(address indexed from, uint256 amount);
    event PlanUpdated(uint256 indexed planVersion, address[] beneficiaries, uint16[] bps);
    event ProposalCreated(
        bytes32 indexed proposalId, uint256 indexed cycle, bytes32 caseId,
        uint256 planVersion, bytes32 attestationHash, uint256 expiresAt
    );
    event SuccessionApproved(bytes32 indexed proposalId, address indexed signer, SignerRole role);
    event ApprovalsInvalidated(uint256 indexed newCycle);
    event Withdrawn(address indexed recipient, uint256 amount);
    event SuccessionOpened(
        bytes32 indexed caseId, uint256 planVersion, bytes32 attestationHash, uint256 windowEnd
    );
    event Cancelled(bytes32 indexed caseId);
    event Paused(address indexed designee, uint256 newWindowEnd);
    event Finalized(uint256 totalAmount, uint256 planVersion);
    event Claimed(address indexed beneficiary, uint256 amount);

    // Custom errors

    error NotOwner();
    error NotDesignee();
    /// @notice The caller is neither a designee nor a notary.
    error NotSigner();
    /// @notice The call is not allowed in the current phase.
    error WrongPhase(Phase current);
    error InvalidRoles();
    error InvalidPlan();
    /// @notice The signer refers to a plan version that is not the current one.
    error StalePlanVersion(uint256 current, uint256 given);
    error AlreadyApproved();
    error WindowStillOpen(uint256 windowEnd);
    error WindowClosed(uint256 windowEnd);
    error PauseAlreadyUsed();
    error NothingToClaim();
    error TransferFailed();
    error StaleApprovalCycle(uint256 current, uint256 given);
    error InvalidProposal();
    error ProposalExpired(uint256 expiresAt);
    error InvalidDuration();
    error InvalidRecipient();
    error InvalidAmount();
    error ReentrantCall();

    // Constants and immutable roles

    /// @notice Shares are expressed in basis points: 10,000 = 100%.
    uint16 public constant TOTAL_BPS = 10_000;
    /// @notice How many of the three designees must approve the opening.
    uint8 public constant DESIGNEE_QUORUM = 2;
    /// @notice Bounds the number of entries processed by `finalize()`.
    uint256 public constant MAX_BENEFICIARIES = 16;
    /// @notice Maximum remaining validity at submission. All signers agree on the SAME deadline.
    /// @dev Demo policy, not a legally prescribed duration. An expired proposal needs a new deadline.
    uint256 public constant MAX_APPROVAL_VALIDITY = 7 days;

    /// @notice The holder. Roles are fixed at deployment: changing them means deploying a new vault.
    address public immutable owner;
    address public immutable notary;
    address public immutable notarySub;
    /// @notice Veto window in seconds, chosen at deployment (e.g. 120 for a demo).
    uint256 public immutable vetoWindow;
    /// @notice By how many seconds a pause extends the window.
    uint256 public immutable pauseDuration;
    /// @notice There are always exactly three designees.
    address[3] public designees;

    // State

    Phase public phase;

    /// @notice Incremented at every plan change. Signers must quote it when opening a succession.
    uint256 public planVersion;
    address[] private _beneficiaries;
    uint16[] private _bps;

    // --- Independent proposals ---

    struct Proposal {
        uint8 designeeApprovals;
        bool notaryApproved;
        uint256 expiresAt;
    }

    /// @notice Changes on cancellation and plan updates, invalidating old approvals/queued calls.
    uint256 public approvalCycle;
    mapping(bytes32 proposalId => Proposal) public proposals;
    mapping(bytes32 proposalId => mapping(address signer => bool)) public hasApproved;
    /// @notice Only set when a proposal reaches quorum; never set by the first approval.
    bytes32 public selectedProposalId;

    // --- Selected succession (reset by cancellation or plan updates) ---

    /// @notice Opaque case identifier agreed off-chain; avoid embedding personal data.
    bytes32 public caseId;
    /// @notice Hash of the attestation document the signers refer to.
    bytes32 public attestationHash;
    uint8 public designeeApprovals;
    bool public notaryApproved;
    /// @notice End of the veto window (unix time). Zero while no succession is open.
    uint256 public windowEnd;
    bool public pauseUsed;

    // --- After finalization ---

    /// @notice Vault balance snapshotted by `finalize()`.
    uint256 public finalizedTotal;
    /// @notice Amount each beneficiary can still withdraw.
    mapping(address beneficiary => uint256) public claimable;

    // Single-file reentrancy guard: all mutating entry points use the same lock.
    uint256 private _entered;

    modifier nonReentrant() {
        if (_entered != 0) revert ReentrantCall();
        _entered = 1;
        _;
        _entered = 0;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // Construction

    /// @param owner_ The holder.
    /// @param designees_ Exactly three distinct designees.
    /// @param notary_ The notary.
    /// @param notarySub_ The substitute notary.
    /// @param vetoWindow_ Veto window in seconds.
    /// @param pauseDuration_ Extension granted by the single pause, in seconds.
    /// @param beneficiaries_ Initial plan: who receives.
    /// @param bps_ Initial plan: shares in basis points, summing to 10,000.
    constructor(
        address owner_,
        address[3] memory designees_,
        address notary_,
        address notarySub_,
        uint256 vetoWindow_,
        uint256 pauseDuration_,
        address[] memory beneficiaries_,
        uint16[] memory bps_
    ) {
        if (owner_ == address(0) || notary_ == address(0) || notarySub_ == address(0)) revert InvalidRoles();
        if (notary_ == notarySub_) revert InvalidRoles();
        for (uint256 i = 0; i < 3; i++) {
            address d = designees_[i];
            // A notary key must never double as a designee key: the two approvals are separate safeguards.
            if (d == address(0) || d == notary_ || d == notarySub_) revert InvalidRoles();
            for (uint256 j = 0; j < i; j++) {
                if (designees_[j] == d) revert InvalidRoles();
            }
        }

        if (vetoWindow_ == 0 || pauseDuration_ == 0) revert InvalidDuration();
        owner = owner_;
        designees = designees_;
        notary = notary_;
        notarySub = notarySub_;
        vetoWindow = vetoWindow_;
        pauseDuration = pauseDuration_;

        _setPlan(beneficiaries_, bps_);
    }

    // Funding

    /// @notice Anyone can fund the vault with a plain transfer.
    receive() external payable nonReentrant {
        _deposit();
    }

    /// @notice Anyone can fund the vault.
    function deposit() external payable nonReentrant {
        _deposit();
    }

    function _deposit() private {
        // Ordinary deposits are blocked once claim amounts have been fixed.
        if (phase == Phase.Finalized) revert WrongPhase(phase);
        emit Deposited(msg.sender, msg.value);
    }

    // Holder actions

    /// @notice Replaces the plan during Active/Opening and invalidates ALL outstanding approvals.
    function updatePlan(address[] calldata beneficiaries_, uint16[] calldata bps_)
        external onlyOwner nonReentrant
    {
        _requireEverydayPhase();
        _setPlan(beneficiaries_, bps_);
        _invalidateApprovals();
    }

    /// @notice Withdraw ETH in Active/Opening. In Window use cancelAndWithdraw instead.
    /// @dev Withdrawals do not change percentage shares or invalidate a pending proposal.
    function withdraw(uint256 amount, address payable recipient) external onlyOwner nonReentrant {
        _requireEverydayPhase();
        _withdraw(amount, recipient);
    }

    /// @notice Atomically invalidates every approval, cancels any window, then withdraws ETH.
    /// @dev Allowed until actual finalization, including after windowEnd. Transaction order matters.
    function cancelAndWithdraw(uint256 amount, address payable recipient)
        external onlyOwner nonReentrant
    {
        if (phase == Phase.Finalized) revert WrongPhase(phase);
        _cancel();
        _withdraw(amount, recipient);
    }

    /// @notice Cancels any proposal/window. A signature proves key control, not that the holder is alive.
    /// @dev The veto remains possible until finalization, even after windowEnd.
    function cancel() external onlyOwner nonReentrant {
        if (phase == Phase.Finalized) revert WrongPhase(phase);
        _cancel();
    }

    // Succession

    /// @notice Approves ONE independently identified proposal. Opening does not lock other proposals.
    /// @dev Two distinct designees AND either notary must approve the exact same parameters before expiry.
    ///      Once quorum is reached, only that proposal enters Window. Expiry then no longer applies:
    ///      the veto deadline governs the selected succession.
    /// @param caseId_ Opaque identifier agreed off-chain (nonzero).
    /// @param planVersion_ Current plan version, read before signing/submitting.
    /// @param attestationHash_ Nonzero document hash; not proof of death.
    /// @param approvalCycle_ Current approvalCycle, read before submitting. Never inferred for old calls.
    /// @param expiresAt_ Shared absolute deadline, at most MAX_APPROVAL_VALIDITY in the future.
    function openSuccession(
        bytes32 caseId_, uint256 planVersion_, bytes32 attestationHash_,
        uint256 approvalCycle_, uint256 expiresAt_
    ) external nonReentrant {
        _requireEverydayPhase();
        bool callerIsDesignee = isDesignee(msg.sender);
        bool callerIsNotary = msg.sender == notary || msg.sender == notarySub;
        if (!callerIsDesignee && !callerIsNotary) revert NotSigner();
        if (planVersion_ != planVersion) revert StalePlanVersion(planVersion, planVersion_);
        if (approvalCycle_ != approvalCycle) revert StaleApprovalCycle(approvalCycle, approvalCycle_);
        if (caseId_ == bytes32(0) || attestationHash_ == bytes32(0)) revert InvalidProposal();
        if (expiresAt_ <= block.timestamp) revert ProposalExpired(expiresAt_);
        if (expiresAt_ - block.timestamp > MAX_APPROVAL_VALIDITY) revert InvalidProposal();

        bytes32 id = getProposalId(caseId_, planVersion_, attestationHash_, approvalCycle_, expiresAt_);
        Proposal storage proposal = proposals[id];
        if (proposal.expiresAt == 0) {
            proposal.expiresAt = expiresAt_;
            emit ProposalCreated(id, approvalCycle_, caseId_, planVersion_, attestationHash_, expiresAt_);
        }
        if (hasApproved[id][msg.sender]) revert AlreadyApproved();
        if (callerIsDesignee) {
            proposal.designeeApprovals++;
            emit SuccessionApproved(id, msg.sender, SignerRole.Designee);
        } else {
            // Both notary keys represent one role, never two votes.
            if (proposal.notaryApproved) revert AlreadyApproved();
            proposal.notaryApproved = true;
            emit SuccessionApproved(id, msg.sender, msg.sender == notary ? SignerRole.Notary : SignerRole.NotarySub);
        }
        hasApproved[id][msg.sender] = true;
        phase = Phase.Opening;

        if (proposal.designeeApprovals >= DESIGNEE_QUORUM && proposal.notaryApproved) {
            selectedProposalId = id;
            caseId = caseId_;
            attestationHash = attestationHash_;
            designeeApprovals = proposal.designeeApprovals;
            notaryApproved = true;
            phase = Phase.Window;
            windowEnd = block.timestamp + vetoWindow;
            emit SuccessionOpened(caseId, planVersion, attestationHash, windowEnd);
        }
    }

    /// @notice Any designee can extend the window once per succession, to raise an objection off-chain.
    /// @dev Not renewable: a second call reverts, whoever makes it.
    function pause() external nonReentrant {
        if (!isDesignee(msg.sender)) revert NotDesignee();
        if (phase != Phase.Window) revert WrongPhase(phase);
        if (block.timestamp >= windowEnd) revert WindowClosed(windowEnd);
        if (pauseUsed) revert PauseAlreadyUsed();

        pauseUsed = true;
        windowEnd += pauseDuration;

        emit Paused(msg.sender, windowEnd);
    }

    /// @notice After the window, ANY caller can execute the already-authorized distribution.
    /// @dev Requires the quorum-backed Window state; the caller cannot choose shares or recipients.
    ///      Example: 10 ETH with a 60/40 plan gives 6 ETH and 4 ETH.
    function finalize() external nonReentrant {
        if (phase != Phase.Window) revert WrongPhase(phase);
        if (block.timestamp < windowEnd) revert WindowStillOpen(windowEnd);

        uint256 total = address(this).balance;
        uint256 distributed = 0;
        uint256 last = _beneficiaries.length - 1;

        for (uint256 i = 0; i < last; i++) {
            uint256 amount = (total * _bps[i]) / TOTAL_BPS;
            claimable[_beneficiaries[i]] += amount;
            distributed += amount;
        }
        // The last beneficiary receives the remainder, so that rounding leaves nothing stuck in the vault.
        claimable[_beneficiaries[last]] += total - distributed;

        finalizedTotal = total;
        phase = Phase.Finalized;

        emit Finalized(total, planVersion);
    }

    /// @notice A beneficiary withdraws their own fixed amount, independently of the others.
    /// @dev Checks-effects-interactions: the amount is zeroed before the transfer, so a second claim
    ///      cannot withdraw the same allocation twice. The shared guard also blocks re-entry.
    function claim() external nonReentrant {
        // Checks
        if (phase != Phase.Finalized) revert WrongPhase(phase);
        uint256 amount = claimable[msg.sender];
        if (amount == 0) revert NothingToClaim();

        // Effects
        claimable[msg.sender] = 0;
        emit Claimed(msg.sender, amount);

        // Interaction
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // Views

    /// @notice Computes a proposal ID, bound to this chain, vault, plan, cycle and expiry.
    /// @dev Historical proposal records remain readable but cannot authorize a newer cycle.
    function getProposalId(
        bytes32 caseId_, uint256 planVersion_, bytes32 attestationHash_,
        uint256 approvalCycle_, uint256 expiresAt_
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            block.chainid, address(this), approvalCycle_, planVersion_, caseId_, attestationHash_, expiresAt_
        ));
    }

    /// @notice True if `account` is one of the three designees.
    function isDesignee(address account) public view returns (bool) {
        return account == designees[0] || account == designees[1] || account == designees[2];
    }

    /// @notice The current plan: beneficiaries and their shares in basis points.
    function getPlan() external view returns (address[] memory beneficiaries, uint16[] memory bps) {
        return (_beneficiaries, _bps);
    }

    // Internal

    function _requireEverydayPhase() private view {
        if (phase != Phase.Active && phase != Phase.Opening) revert WrongPhase(phase);
    }

    function _withdraw(uint256 amount, address payable recipient) private {
        if (recipient == address(0) || recipient == address(this)) revert InvalidRecipient();
        if (amount == 0 || amount > address(this).balance) revert InvalidAmount();
        emit Withdrawn(recipient, amount);
        (bool ok,) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function _cancel() private {
        bytes32 cancelledCase = caseId; // zero if no proposal had reached quorum
        _invalidateApprovals();
        emit Cancelled(cancelledCase);
    }

    function _invalidateApprovals() private {
        // O(1) invalidation. No unbounded iteration over proposals, and no stale transaction replay.
        approvalCycle++;
        delete selectedProposalId;
        delete caseId;
        delete attestationHash;
        delete designeeApprovals;
        delete notaryApproved;
        delete windowEnd;
        delete pauseUsed;
        phase = Phase.Active;
        emit ApprovalsInvalidated(approvalCycle);
    }

    /// @dev Validates and stores a plan, then bumps the version.
    function _setPlan(address[] memory beneficiaries_, uint16[] memory bps_) private {
        uint256 n = beneficiaries_.length;
        if (n == 0 || n > MAX_BENEFICIARIES || n != bps_.length) revert InvalidPlan();

        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            if (beneficiaries_[i] == address(0) || bps_[i] == 0) revert InvalidPlan();
            sum += bps_[i];
        }
        if (sum != TOTAL_BPS) revert InvalidPlan();

        _beneficiaries = beneficiaries_;
        _bps = bps_;
        planVersion++;

        emit PlanUpdated(planVersion, beneficiaries_, bps_);
    }
}
