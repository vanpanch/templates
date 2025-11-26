// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

abstract contract EVMAuthAccessControl is AccessControlDefaultAdminRules {
    // Roles
    bytes32 public constant BLACKLIST_MANAGER_ROLE =
        keccak256("BLACKLIST_MANAGER_ROLE");

    // Mapping for account address -> blacklisted status
    mapping(address => bool) private _blacklisted;

    // Events
    event AddedToBlacklist(address indexed account);
    event RemovedFromBlacklist(address indexed account);

    // Modifiers
    modifier denyBlacklisted(address account) {
        require(!isBlacklisted(account), "Account is blacklisted");
        _;
    }

    modifier denyBlacklistedSender() {
        require(!isBlacklisted(_msgSender()), "Sender is blacklisted");
        _;
    }

    constructor(
        uint48 _delay,
        address _owner
    ) AccessControlDefaultAdminRules(_delay, _owner) {
        _grantRole(BLACKLIST_MANAGER_ROLE, _owner);
    }

    function addToBlacklist(
        address account
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        require(
            !hasRole(BLACKLIST_MANAGER_ROLE, account),
            "Account is a blacklist manager"
        );
        require(account != address(0), "Account is the zero address");

        _blacklisted[account] = true;

        emit AddedToBlacklist(account);
    }

    function addBatchToBlacklist(
        address[] memory accounts
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blacklisted[accounts[i]] = true;
        }
    }

    function grantRoles(
        bytes32[] memory roles,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) denyBlacklisted(account) {
        for (uint256 i = 0; i < roles.length; i++) {
            // Skip DEFAULT_ADMIN_ROLE as it's handled by AccessControlDefaultAdminRules
            if (roles[i] == DEFAULT_ADMIN_ROLE) continue;

            grantRole(roles[i], account);
        }
    }

    function isBlacklisted(address account) public view returns (bool) {
        if (account == address(0)) {
            return _blacklisted[_msgSender()];
        }
        return _blacklisted[account];
    }

    function removeFromBlacklist(
        address account
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        delete _blacklisted[account];

        emit RemovedFromBlacklist(account);
    }

    function removeBatchFromBlacklist(
        address[] memory accounts
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blacklisted[accounts[i]] = false;
        }
    }

    function revokeRoles(
        bytes32[] memory roles,
        address account
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < roles.length; i++) {
            // Skip DEFAULT_ADMIN_ROLE as it's handled by AccessControlDefaultAdminRules
            if (roles[i] == DEFAULT_ADMIN_ROLE) continue;

            revokeRole(roles[i], account);
        }
    }
}

abstract contract EVMAuthBaseERC1155 is
    ERC1155,
    EVMAuthAccessControl,
    ReentrancyGuard
{
    // Unique project identifier, for cross-chain consistency
    bytes32 public immutable PROJECT_ID;

    // Roles
    bytes32 public constant TOKEN_MANAGER_ROLE =
        keccak256("TOKEN_MANAGER_ROLE");
    bytes32 public constant TOKEN_MINTER_ROLE = keccak256("TOKEN_MINTER_ROLE");
    bytes32 public constant TOKEN_BURNER_ROLE = keccak256("TOKEN_BURNER_ROLE");

    // Data structure for token metadata
    struct BaseMetadata {
        uint256 id;
        bool active;
        bool burnable;
        bool transferable;
    }

    // Mapping from token ID to metadata
    mapping(uint256 => BaseMetadata) private _metadata;

    // Auto-incrementing token ID
    uint256 internal nextTokenId = 0;

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) ERC1155(_uri) EVMAuthAccessControl(_delay, _owner) {
        // Generate a unique project identifier using the keccak256 hash of the name
        PROJECT_ID = keccak256(abi.encodePacked(_name, _version));

        // Grant all roles to the contract owner
        _grantRole(TOKEN_MANAGER_ROLE, _owner);
        _grantRole(TOKEN_MINTER_ROLE, _owner);
        _grantRole(TOKEN_BURNER_ROLE, _owner);
    }

    function active(uint256 id) public view returns (bool) {
        return _metadata[id].active;
    }

    function baseMetadataOf(
        uint256 id
    ) public view returns (BaseMetadata memory) {
        return _metadata[id];
    }

    function baseMetadataOfAll() public view returns (BaseMetadata[] memory) {
        BaseMetadata[] memory result = new BaseMetadata[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _metadata[i];
        }
        return result;
    }

    function baseMetadataOfBatch(
        uint256[] memory ids
    ) public view returns (BaseMetadata[] memory) {
        BaseMetadata[] memory result = new BaseMetadata[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _metadata[ids[i]];
        }
        return result;
    }

    function burn(address from, uint256 id, uint256 amount) external {
        require(
            hasRole(TOKEN_BURNER_ROLE, _msgSender()),
            "Unauthorized burner"
        );
        _burn(from, id, amount);
    }

    function burnable(uint256 id) public view returns (bool) {
        return _metadata[id].burnable;
    }

    function burnBatch(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external {
        require(
            hasRole(TOKEN_BURNER_ROLE, _msgSender()),
            "Unauthorized burner"
        );
        _burnBatch(from, ids, amounts);
    }

    function isApprovedForAll(
        address account,
        address operator
    ) public view virtual override returns (bool) {
        if (isBlacklisted(account) || isBlacklisted(operator)) {
            return false;
        }
        return super.isApprovedForAll(account, operator);
    }

    function issue(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external {
        require(
            hasRole(TOKEN_MINTER_ROLE, _msgSender()),
            "Unauthorized minter"
        );
        _mint(to, id, amount, data);
    }

    function issueBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        require(
            hasRole(TOKEN_MINTER_ROLE, _msgSender()),
            "Unauthorized minter"
        );
        _mintBatch(to, ids, amounts, data);
    }

    function transferable(uint256 id) public view returns (bool) {
        return _metadata[id].transferable;
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes memory data
    ) public virtual override {
        super.safeTransferFrom(from, to, id, value, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values,
        bytes memory data
    ) public virtual override {
        super.safeBatchTransferFrom(from, to, ids, values, data);
    }

    function setApprovalForAll(
        address operator,
        bool approved
    ) public virtual override denyBlacklisted(operator) denyBlacklistedSender {
        super.setApprovalForAll(operator, approved);
    }

    function setBaseMetadata(
        uint256 id,
        bool _active,
        bool _burnable,
        bool _transferable
    ) public {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );
        require(id <= nextTokenId, "Invalid token ID");

        _metadata[id] = BaseMetadata(id, _active, _burnable, _transferable);

        if (id == nextTokenId) {
            nextTokenId++;
        }
    }

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC1155, AccessControlDefaultAdminRules)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    )
        internal
        virtual
        override
        denyBlacklisted(from)
        denyBlacklisted(to)
        denyBlacklistedSender
    {
        for (uint256 i = 0; i < ids.length; i++) {
            // Minting
            if (from == address(0)) {
                require(active(ids[i]), "Token is not active");
            }
            // Burning
            else if (to == address(0)) {
                require(burnable(ids[i]), "Token is not burnable");
            }
            // Transferring
            else {
                require(active(ids[i]), "Token is not active");
                require(transferable(ids[i]), "Token is not transferable");
            }
        }

        super._update(from, to, ids, values);
    }
}

abstract contract EVMAuthPurchasableERC1155 is EVMAuthBaseERC1155 {
    // Wallet address for receiving payments
    address public wallet;

    // Roles
    bytes32 public constant FINANCE_MANAGER_ROLE =
        keccak256("FINANCE_MANAGER_ROLE");

    // Mapping from token ID to price
    mapping(uint256 => uint256) private _prices;

    // Events
    event FundsWithdrawn(address indexed wallet, uint256 amount);
    event TokenPurchased(
        address indexed account,
        uint256 indexed id,
        uint256 amount
    );
    event WalletChanged(address indexed oldWallet, address indexed newWallet);

    // Modifiers
    modifier requireForSale(uint256 id) {
        require(forSale(id), "Token is not for sale");
        _;
    }

    modifier requirePrice(uint256 id) {
        require(priceOf(id) > 0, "Token is priceless");
        _;
    }

    modifier requireValidWallet(address account) {
        // Check that the wallet address is not the zero address or this contract address
        require(account != address(0), "Invalid wallet address");
        require(account != address(this), "Invalid wallet address");
        _;
    }

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) EVMAuthBaseERC1155(_name, _version, _uri, _delay, _owner) {
        // Grant all roles to the contract owner
        _grantRole(FINANCE_MANAGER_ROLE, _owner);

        // Set the initial wallet address to this contract address
        wallet = _owner;
    }

    function forSale(uint256 id) public view returns (bool) {
        return active(id) && _prices[id] > 0;
    }

    function priceOf(uint256 id) public view returns (uint256) {
        return _prices[id];
    }

    function priceOfAll() public view returns (uint256[] memory result) {
        result = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _prices[i];
        }
        return result;
    }

    function priceOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory result) {
        result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _prices[ids[i]];
        }
        return result;
    }

    function purchase(
        address account,
        uint256 id,
        uint256 amount
    )
        external
        payable
        nonReentrant
        denyBlacklisted(account)
        denyBlacklistedSender
        requireForSale(id)
        requireValidWallet(wallet)
    {
        // If account is zero, use the sender's address
        if (account == address(0)) {
            account = _msgSender();
        }

        // Calculate the total price
        uint256 totalPrice = priceOf(id) * amount;
        require(msg.value >= totalPrice, "Insufficient payment");

        // Refund any excess payment
        uint256 refund = msg.value - totalPrice;
        if (refund > 0) {
            payable(_msgSender()).transfer(refund);
        }

        // Transfer the payment to the wallet
        payable(wallet).transfer(totalPrice);

        // Mint the purchased tokens to the buyer
        _mint(account, id, amount, "");

        emit TokenPurchased(account, id, amount);
    }

    function setPriceOf(
        uint256 id,
        uint256 price
    ) public denyBlacklistedSender {
        require(
            hasRole(FINANCE_MANAGER_ROLE, _msgSender()),
            "Unauthorized finance manager"
        );
        _prices[id] = price;
    }

    function setPriceOfBatch(
        uint256[] memory ids,
        uint256[] memory prices
    ) external denyBlacklistedSender {
        require(
            hasRole(FINANCE_MANAGER_ROLE, _msgSender()),
            "Unauthorized finance manager"
        );
        require(ids.length == prices.length, "Array lengths do not match");
        for (uint256 i = 0; i < ids.length; i++) {
            _prices[ids[i]] = prices[i];
        }
    }

    function setWallet(address value) external requireValidWallet(value) {
        require(
            hasRole(FINANCE_MANAGER_ROLE, _msgSender()),
            "Unauthorized finance manager"
        );
        address oldWallet = wallet;
        wallet = value;
        emit WalletChanged(oldWallet, value);
    }

    function withdraw()
        external
        payable
        nonReentrant
        requireValidWallet(wallet)
    {
        require(
            hasRole(FINANCE_MANAGER_ROLE, _msgSender()),
            "Unauthorized finance manager"
        );

        uint256 balance = address(this).balance;
        require(balance > 0, "No funds to withdraw");

        payable(wallet).transfer(balance);

        emit FundsWithdrawn(wallet, balance);
    }
}

abstract contract EVMAuthExpiringERC1155 is EVMAuthPurchasableERC1155 {
    // Batch of tokens that expire at the same time
    struct Group {
        uint256 balance;
        uint256 expiresAt;
    }

    // Mapping from account -> token ID -> Group[]
    mapping(address => mapping(uint256 => Group[])) private _group;

    // Mapping from token ID to token time-to-live (TTL) in seconds
    mapping(uint256 => uint256) private _ttls;

    // Events
    event ExpiredTokensBurned(
        address indexed account,
        uint256 indexed id,
        uint256 amount
    );

    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) EVMAuthPurchasableERC1155(_name, _version, _uri, _delay, _owner) {}

    function balanceOf(
        address account,
        uint256 id
    ) public view override returns (uint256) {
        Group[] storage groups = _group[account][id];
        uint256 netBalance = super.balanceOf(account, id);
        uint256 _now = block.timestamp;

        // Exclude expired token balances
        for (uint256 i = 0; i < groups.length; i++) {
            if (groups[i].expiresAt <= _now) {
                netBalance -= groups[i].balance;
            }
        }

        return netBalance;
    }

    function balanceOfAll(
        address account
    ) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            balances[i] = balanceOf(account, i);
        }
        return balances;
    }

    function balanceOfBatch(
        address[] memory accounts,
        uint256[] memory ids
    ) public view override returns (uint256[] memory) {
        require(accounts.length == ids.length, "Length mismatch");
        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; i++) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    function balanceDetailsOf(
        address account,
        uint256 id
    ) external view returns (Group[] memory) {
        return _validGroups(account, id);
    }

    function balanceDetailsOfAll(
        address account
    ) external view returns (Group[][] memory) {
        Group[][] memory result = new Group[][](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _validGroups(account, i);
        }
        return result;
    }

    function balanceDetailsOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (Group[][] memory result) {
        require(accounts.length == ids.length, "Length mismatch");
        result = new Group[][](accounts.length);

        for (uint256 i = 0; i < accounts.length; i++) {
            result[i] = _validGroups(accounts[i], ids[i]);
        }

        return result;
    }

    function _burnGroupBalances(
        address account,
        uint256 id,
        uint256 amount
    ) internal {
        Group[] storage groups = _group[account][id];
        uint256 _now = block.timestamp;
        uint256 debt = amount;

        uint256 i = 0;
        while (i < groups.length && debt > 0) {
            if (groups[i].expiresAt <= _now) {
                i++;
                continue;
            }

            if (groups[i].balance > debt) {
                // Burn partial token group
                groups[i].balance -= debt;
                debt = 0;
            } else {
                // Burn entire token group
                debt -= groups[i].balance;
                groups[i].balance = 0;
            }
            i++;
        }
    }

    function expirationFor(uint256 id) public view returns (uint256) {
        return ttlOf(id) == 0 ? type(uint256).max : block.timestamp + ttlOf(id);
    }

    function _pruneGroups(address account, uint256 id) internal {
        Group[] storage groups = _group[account][id];
        uint256 _now = block.timestamp;

        // Shift valid groups to the front of the array
        uint256 index = 0;
        uint256 expiredAmount = 0;
        for (uint256 i = 0; i < groups.length; i++) {
            bool isValid = groups[i].balance > 0 && groups[i].expiresAt > _now;
            if (isValid) {
                if (i != index) {
                    groups[index] = groups[i];
                }
                index++;
            } else {
                expiredAmount += groups[i].balance;
            }
        }

        // Remove invalid groups from the end of the array
        while (groups.length > index) {
            groups.pop();
        }

        // If any expired groups were removed, emit an event with the total amount of expired tokens
        if (expiredAmount > 0) {
            emit ExpiredTokensBurned(account, id, expiredAmount);
        }
    }

    function _transferGroups(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) internal {
        // Exit early if the transfer is to the same account or if the amount is zero
        if (from == to || amount == 0) return;

        Group[] storage groups = _group[from][id];
        uint256 _now = block.timestamp;
        uint256 debt = amount;

        // First pass: Reduce balances from sender's groups (FIFO order)
        for (uint256 i = 0; i < groups.length && debt > 0; i++) {
            // Skip token groups that are expired or have no balance
            if (groups[i].expiresAt <= _now || groups[i].balance == 0) {
                continue;
            }

            if (groups[i].balance > debt) {
                // Transfer partial token group
                _upsertGroup(to, id, debt, groups[i].expiresAt);
                groups[i].balance -= debt;
                debt = 0;
            } else {
                // Transfer entire token group
                _upsertGroup(to, id, groups[i].balance, groups[i].expiresAt);
                debt -= groups[i].balance;
                groups[i].balance = 0;
            }
        }

        // Clean up from account token groups that are expired or have zero balance
        _pruneGroups(from, id);
    }

    function setTTL(uint256 id, uint256 value) public {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );
        require(burnable(id), "Token is not burnable, so it cannot expire");
        _ttls[id] = value;
    }

    function ttlOf(uint256 id) public view returns (uint256) {
        return _ttls[id];
    }

    function ttlOfAll() public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _ttls[i];
        }
        return result;
    }

    function ttlOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _ttls[ids[i]];
        }
        return result;
    }

    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) internal virtual override {
        super._update(from, to, ids, values);

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 _id = ids[i];
            uint256 _amount = values[i];

            // Minting
            if (from == address(0)) {
                address _account = to;
                uint256 _expiresAt = expirationFor(_id);
                _upsertGroup(_account, _id, _amount, _expiresAt);
            }
            // Burning
            else if (to == address(0)) {
                address _account = to;
                _burnGroupBalances(_account, _id, _amount);
                _pruneGroups(_account, _id);
            }
            // Transferring
            else {
                _transferGroups(from, to, _id, _amount);
            }
        }
    }

    function _upsertGroup(
        address account,
        uint256 id,
        uint256 amount,
        uint256 expiresAt
    ) internal {
        Group[] storage groups = _group[account][id];

        // Find the correct position to insert the group (ordered by expiration, oldest to newest)
        uint256 insertIndex = groups.length;
        for (uint256 i = 0; i < groups.length; i++) {
            // Check if this is an insert or an update
            if (groups[i].expiresAt > expiresAt) {
                // Insert the new token group at this position
                insertIndex = i;
                break;
            } else if (groups[i].expiresAt == expiresAt) {
                // If a token group with same expiration exists, combine the balances and return
                groups[i].balance += amount;
                return;
            }
        }

        // If the new token group expires later than all the others, add it to the end of the array and return
        if (insertIndex == groups.length) {
            groups.push(Group({balance: amount, expiresAt: expiresAt}));
            return;
        }

        // Shift array elements to make room for the new token group
        groups.push(Group({balance: 0, expiresAt: 0})); // Add space at the end
        for (uint256 i = groups.length - 1; i > insertIndex; i--) {
            groups[i] = groups[i - 1];
        }

        // Insert the new Group at the correct position
        groups[insertIndex] = Group({balance: amount, expiresAt: expiresAt});
    }

    function _validGroups(
        address account,
        uint256 id
    ) internal view returns (Group[] memory) {
        // First, check if the account has any tokens
        uint256 balance = super.balanceOf(account, id);
        if (balance == 0) {
            // Return an empty array
            return new Group[](0);
        }

        Group[] storage groups = _group[account][id];
        uint256 _now = block.timestamp;

        // Count the groups that are not expired and have a balance
        uint256 validBatchCount = 0;
        for (uint256 i = 0; i < groups.length; i++) {
            if (groups[i].expiresAt > _now && groups[i].balance > 0) {
                validBatchCount++;
            }
        }

        // Create a new array of the correct size for valid groups
        Group[] memory details = new Group[](validBatchCount);
        uint256 index = 0;

        // Fill the array with valid groups, in the correct order (earliest expiration first)
        for (uint256 i = 0; i < groups.length; i++) {
            if (groups[i].expiresAt > _now && groups[i].balance > 0) {
                details[index] = groups[i];
                index++;
            }
        }

        return details;
    }
}

contract EVMAuth is EVMAuthExpiringERC1155 {
    // Data structure for token metadata, including price and TTL
    struct TokenMetadata {
        uint256 id;
        bool active;
        bool burnable;
        bool transferable;
        uint256 price;
        uint256 ttl;
    }

    // Events
    event TokenMetadataCreated(uint256 indexed id, TokenMetadata metadata);
    event TokenMetadataUpdated(
        uint256 indexed id,
        TokenMetadata oldMetadata,
        TokenMetadata newMetadata
    );

    constructor(
        string memory name,
        string memory version,
        string memory uri,
        uint48 delay,
        address owner
    ) EVMAuthExpiringERC1155(name, version, uri, delay, owner) {}

    function metadataOf(uint256 id) public view returns (TokenMetadata memory) {
        // Retrieve the base token metadata
        BaseMetadata memory baseMetadata = baseMetadataOf(id);

        // Retrieve the price and TTL for the token
        uint256 price = priceOf(id);
        uint256 ttl = ttlOf(id);

        // Combine all metadata into a single structure
        TokenMetadata memory metadata = TokenMetadata({
            id: baseMetadata.id,
            active: baseMetadata.active,
            burnable: baseMetadata.burnable,
            transferable: baseMetadata.transferable,
            price: price,
            ttl: ttl
        });

        return metadata;
    }

    function metadataOfAll() public view returns (TokenMetadata[] memory) {
        TokenMetadata[] memory result = new TokenMetadata[](nextTokenId);

        // Use *OfAll methods to efficiently collect metadata
        BaseMetadata[] memory baseMetadataArray = baseMetadataOfAll();
        uint256[] memory priceArray = priceOfAll();
        uint256[] memory ttlArray = ttlOfAll();

        // Combine all metadata into a single structure
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = TokenMetadata({
                id: baseMetadataArray[i].id,
                active: baseMetadataArray[i].active,
                burnable: baseMetadataArray[i].burnable,
                transferable: baseMetadataArray[i].transferable,
                price: priceArray[i],
                ttl: ttlArray[i]
            });
        }

        return result;
    }

    function metadataOfBatch(
        uint256[] memory ids
    ) public view returns (TokenMetadata[] memory) {
        TokenMetadata[] memory result = new TokenMetadata[](ids.length);

        // Use *OfBatch methods to efficiently collect metadata
        BaseMetadata[] memory baseMetadataArray = baseMetadataOfBatch(ids);
        uint256[] memory priceArray = priceOfBatch(ids);
        uint256[] memory ttlArray = ttlOfBatch(ids);

        // Combine all metadata into a single structure
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = TokenMetadata({
                id: baseMetadataArray[i].id,
                active: baseMetadataArray[i].active,
                burnable: baseMetadataArray[i].burnable,
                transferable: baseMetadataArray[i].transferable,
                price: priceArray[i],
                ttl: ttlArray[i]
            });
        }

        return result;
    }

    function setMetadata(
        uint256 id,
        bool _active,
        bool _burnable,
        bool _transferable,
        uint256 _price,
        uint256 _ttl
    ) external {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );

        // If the token ID already exists, capture its current state
        bool isUpdate = id < nextTokenId;
        TokenMetadata memory oldMetadata;
        if (isUpdate) {
            oldMetadata = metadataOf(id);
        }

        // Set base token metadata
        setBaseMetadata(id, _active, _burnable, _transferable);

        // Set token price (requires FINANCE_MANAGER_ROLE)
        if (hasRole(FINANCE_MANAGER_ROLE, _msgSender())) {
            setPriceOf(id, _price);
        }

        // Set token TTL (only if token is burnable)
        if (_burnable) {
            setTTL(id, _ttl);
        }

        // Emit event for token metadata creation or update
        TokenMetadata memory newMetadata = metadataOf(id);
        if (isUpdate) {
            emit TokenMetadataUpdated(id, oldMetadata, newMetadata);
        } else {
            emit TokenMetadataCreated(id, newMetadata);
        }
    }

    function setURI(string memory value) external {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );
        _setURI(value);
    }
}
