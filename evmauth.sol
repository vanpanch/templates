// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/**
 * @title EVMAuthAccessControl
 * @dev Extension of OpenZeppelin's AccessControlDefaultAdminRules contract that adds blacklist functionality
 */
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

    /**
     * @dev Constructor
     * @param _delay Delay (in seconds) for transfer of contract ownership
     * @param _owner Address of the contract owner
     */
    constructor(
        uint48 _delay,
        address _owner
    ) AccessControlDefaultAdminRules(_delay, _owner) {
        _grantRole(BLACKLIST_MANAGER_ROLE, _owner);
    }

    /**
     * @dev Add a account to the blacklist; cannot blacklist a blacklist manager or the zero address
     * @param account The address of the account to blacklist
     */
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

    /**
     * @dev Add a batch of accounts to the blacklist
     * @param accounts The addresses of the accounts to blacklist
     */
    function addBatchToBlacklist(
        address[] memory accounts
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blacklisted[accounts[i]] = true;
        }
    }

    /**
     * @dev Grant multiple roles to an account
     * @param roles Array of role identifiers to grant
     * @param account The address to grant the roles to
     */
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

    /**
     * @dev Check if a account is blacklisted; if no account is provided, check if the sender is blacklisted
     * @param account The address of the account to check
     * @return True if the account is blacklisted, false otherwise
     */
    function isBlacklisted(address account) public view returns (bool) {
        if (account == address(0)) {
            return _blacklisted[_msgSender()];
        }
        return _blacklisted[account];
    }

    /**
     * @dev Remove a account from the blacklist
     * @param account The address of the account to remove from the blacklist
     */
    function removeFromBlacklist(
        address account
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        delete _blacklisted[account];

        emit RemovedFromBlacklist(account);
    }

    /**
     * @dev Remove a batch of accounts from the blacklist
     * @param accounts The addresses of the accounts to remove from the blacklist
     */
    function removeBatchFromBlacklist(
        address[] memory accounts
    ) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint256 i = 0; i < accounts.length; i++) {
            _blacklisted[accounts[i]] = false;
        }
    }

    /**
     * @dev Revoke multiple roles from an account
     * @param roles Array of role identifiers to revoke
     * @param account The address to revoke the roles from
     */
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

/**
 * @title EVMAuthBaseERC1155
 * @dev Extension of OpenZeppelin's ERC-1155 contract that adds support for blacklisting, fund withdrawal,
 *      and token management functionality.
 */
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

    /**
     * @dev Constructor
     * @param _name Name identifier for the project
     * @param _version Version identifier for the project
     * @param _uri URI for ERC-1155 token metadata (e.g., "https://example.com/token/{id}.json")
     * @param _delay Delay (in seconds) for transfer of contract ownership
     * @param _owner Address of the contract owner
     */
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

    /**
     * @dev Check if a token is active
     * @param id The ID of the token to check
     * @return True if the token is active, false otherwise
     */
    function active(uint256 id) public view returns (bool) {
        return _metadata[id].active;
    }

    /**
     * @dev Get the metadata of a token
     * @param id The ID of the token to check
     * @return The metadata of the token
     */
    function baseMetadataOf(
        uint256 id
    ) public view returns (BaseMetadata memory) {
        return _metadata[id];
    }

    /**
     * @dev Get the metadata of all tokens
     * @return result The metadata of all tokens
     */
    function baseMetadataOfAll() public view returns (BaseMetadata[] memory) {
        BaseMetadata[] memory result = new BaseMetadata[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _metadata[i];
        }
        return result;
    }

    /**
     * @dev Get the metadata of a batch of tokens
     * @param ids The IDs of the tokens to check
     * @return result The metadata of the tokens
     */
    function baseMetadataOfBatch(
        uint256[] memory ids
    ) public view returns (BaseMetadata[] memory) {
        BaseMetadata[] memory result = new BaseMetadata[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _metadata[ids[i]];
        }
        return result;
    }

    /**
     * @dev Burn a token from an address; token must be burnable
     * @param from Address to burn tokens from
     * @param id Token ID to burn
     * @param amount Amount of tokens to burn
     */
    function burn(address from, uint256 id, uint256 amount) external {
        require(
            hasRole(TOKEN_BURNER_ROLE, _msgSender()),
            "Unauthorized burner"
        );
        _burn(from, id, amount);
    }

    /**
     * @dev Check if a token is burnable
     * @param id The ID of the token to check
     * @return True if the token is burnable, false otherwise
     */
    function burnable(uint256 id) public view returns (bool) {
        return _metadata[id].burnable;
    }

    /**
     * @dev Burn a batch of tokens from an address; tokens must be burnable
     * @param from Address to burn tokens from
     * @param ids Array of token IDs to burn
     * @param amounts Array of amounts to burn
     */
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

    /**
     * @dev Override to return false for blacklisted accounts
     */
    function isApprovedForAll(
        address account,
        address operator
    ) public view virtual override returns (bool) {
        if (isBlacklisted(account) || isBlacklisted(operator)) {
            return false;
        }
        return super.isApprovedForAll(account, operator);
    }

    /**
     * @dev Mint a new token and issue it to an address; token must be active
     * @param to Address to mint tokens to
     * @param id Token ID to mint
     * @param amount Amount of tokens to mint
     * @param data Additional data
     */
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

    /**
     * @dev Mint a batch of tokens and issue them to an address; tokens must be active
     * @param to Address to mint tokens to
     * @param ids Array of token IDs to mint
     * @param amounts Array of amounts to mint
     * @param data Additional data
     */
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

    /**
     * @dev Check if a token is transferable
     * @param id The ID of the token to check
     * @return True if the token is transferable, false otherwise
     */
    function transferable(uint256 id) public view returns (bool) {
        return _metadata[id].transferable;
    }

    /**
     * @dev Override to deny blacklisted accounts
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 value,
        bytes memory data
    ) public virtual override {
        super.safeTransferFrom(from, to, id, value, data);
    }

    /**
     * @dev Override to deny blacklisted accounts
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values,
        bytes memory data
    ) public virtual override {
        super.safeBatchTransferFrom(from, to, ids, values, data);
    }

    /**
     * @dev Override to deny blacklisted accounts
     */
    function setApprovalForAll(
        address operator,
        bool approved
    ) public virtual override denyBlacklisted(operator) denyBlacklistedSender {
        super.setApprovalForAll(operator, approved);
    }

    /**
     * @dev Set the base metadata for a token
     * @param id The ID of the token
     * @param _active Whether the token is active
     * @param _burnable Whether the token is burnable
     * @param _transferable Whether the token is transferable
     */
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

    /**
     * @dev Override to declare support for interfaces
     */
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

    /**
     * @dev Override to deny blacklisted accounts when minting, burning, or transferring tokens
     */
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

/**
 * @title EVMAuthPurchasableERC1155
 * @dev Extension of the EVMAuthBaseERC1155 contract that enables the direct purchase and price management of tokens
 */
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

    /**
     * @dev Constructor
     * @param _name Name of the EIP-712 signing domain
     * @param _version Current major version of the EIP-712 signing domain
     * @param _uri URI for ERC-1155 token metadata
     * @param _delay Delay (in seconds) for transfer of contract ownership
     * @param _owner Address of the contract owner
     */
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

    /**
     * @dev Check if a token is active and has a price greater than 0
     * @param id The ID of the token to check
     * @return True if the token is purchasable, false otherwise
     */
    function forSale(uint256 id) public view returns (bool) {
        return active(id) && _prices[id] > 0;
    }

    /**
     * @dev Get the price of a token
     * @param id The ID of the token to check
     * @return The price of the token
     */
    function priceOf(uint256 id) public view returns (uint256) {
        return _prices[id];
    }

    /**
     * @dev Get the price of all tokens
     * @return result The prices of all tokens
     */
    function priceOfAll() public view returns (uint256[] memory result) {
        result = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _prices[i];
        }
        return result;
    }

    /**
     * @dev Get the purchasing metadata for a batch of tokens
     * @param ids The IDs of the tokens to check
     * @return result The purchasing metadata for the tokens
     */
    function priceOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory result) {
        result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _prices[ids[i]];
        }
        return result;
    }

    /**
     * @dev Purchase a token for a specific account
     * @param id The ID of the token to purchase
     * @param amount The amount of tokens to purchase
     */
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

    /**
     * @dev Set the price for a token
     * @param id The ID of the token to set the price for
     * @param price The price of the token
     */
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

    /**
     * @dev Set the price for a batch of tokens
     * @param ids The IDs of the tokens to set the price for
     * @param prices The prices of the tokens
     */
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

    /**
     * @dev Set the wallet address for receiving payments
     * @param value The new wallet address
     */
    function setWallet(address value) external requireValidWallet(value) {
        require(
            hasRole(FINANCE_MANAGER_ROLE, _msgSender()),
            "Unauthorized finance manager"
        );
        address oldWallet = wallet;
        wallet = value;
        emit WalletChanged(oldWallet, value);
    }

    /**
     * @dev Move balance from this contract to wallet address
     */
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

/**
 * @title EVMAuthExpiringERC1155
 * @dev Extension of the EVMAuthPurchasableERC1155 contract that adds expiration logic and management to tokens
 */
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

    /**
     * @dev Constructor
     * @param _name Name of the EIP-712 signing domain
     * @param _version Current major version of the EIP-712 signing domain
     * @param _uri URI for ERC-1155 token metadata
     * @param _delay Delay (in seconds) for transfer of contract ownership
     * @param _owner Address of the contract owner
     */
    constructor(
        string memory _name,
        string memory _version,
        string memory _uri,
        uint48 _delay,
        address _owner
    ) EVMAuthPurchasableERC1155(_name, _version, _uri, _delay, _owner) {}

    /**
     * @dev Override to exclude expired tokens
     */
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

    /**
     * @dev Get the balance of all tokens for a given account
     * @param account The address to check
     * @return Array of balances for each token ID
     */
    function balanceOfAll(
        address account
    ) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            balances[i] = balanceOf(account, i);
        }
        return balances;
    }

    /**
     * @dev Override to exclude expired tokens
     */
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

    /**
     * @dev Get expiration details of token holdings for an account
     * @param account The address to check
     * @param id The token ID to check
     * @return Array of Group structs, with amount and expiration of each batch
     */
    function balanceDetailsOf(
        address account,
        uint256 id
    ) external view returns (Group[] memory) {
        return _validGroups(account, id);
    }

    /**
     * @dev Get expiration details of token holdings for all tokens of an account
     * @param account The address to check
     * @return Array of Group arrays, with amount and expiration of each batch for each token ID
     */
    function balanceDetailsOfAll(
        address account
    ) external view returns (Group[][] memory) {
        Group[][] memory result = new Group[][](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _validGroups(account, i);
        }
        return result;
    }

    /**
     * @dev Get expiration details of token holdings for multiple accounts
     * @param accounts Array of addresses to check
     * @param ids Array of token IDs to check
     * @return result Array of Group arrays, with amount and expiration of each batch for each account
     */
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

    /**
     * @dev Adjust the token group balances in first-in-first-out (FIFO) order (earliest expiration first)
     * @param account The address of the account
     * @param id The ID of the token
     * @param amount The amount of tokens to burn
     */
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

    /**
     * @dev Generate the expiration timestamp for a token ID
     * @param id The ID of the token
     * @return The expiration timestamp (in seconds) for the token
     */
    function expirationFor(uint256 id) public view returns (uint256) {
        return ttlOf(id) == 0 ? type(uint256).max : block.timestamp + ttlOf(id);
    }

    /**
     * @dev Delete token groups that are expired or have no balance
     * @param account The address whose token groups need pruning
     * @param id The ID of the token
     */
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

    /**
     * @dev Transfer token groups from one account to another
     * @param from The source address
     * @param to The destination address
     * @param id The ID of the token
     * @param amount The amount of tokens to transfer
     */
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

    /**
     * @dev Set the time-to-live (TTL) for a token
     * @param id The ID of the token
     * @param value The TTL (in seconds) for the token; set to 0 (default) for perpetual tokens
     */
    function setTTL(uint256 id, uint256 value) public {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );
        require(burnable(id), "Token is not burnable, so it cannot expire");
        _ttls[id] = value;
    }

    /**
     * @dev Get the time-to-live (TTL) for a token
     * @param id The ID of the token
     * @return The TTL (in seconds) for the token
     */
    function ttlOf(uint256 id) public view returns (uint256) {
        return _ttls[id];
    }

    /**
     * @dev Get the time-to-live (TTL) for all tokens
     * @return result The TTL (in seconds) for each token
     */
    function ttlOfAll() public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](nextTokenId);
        for (uint256 i = 0; i < nextTokenId; i++) {
            result[i] = _ttls[i];
        }
        return result;
    }

    /**
     * @dev Get the time-to-live (TTL) for a batch of tokens
     * @param ids The IDs of the tokens
     * @return result The TTL (in seconds) for each token in the batch
     */
    function ttlOfBatch(
        uint256[] memory ids
    ) public view returns (uint256[] memory) {
        uint256[] memory result = new uint256[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            result[i] = _ttls[ids[i]];
        }
        return result;
    }

    /**
     * @dev Override to update token expiration data on mint, burn, and transfer
     */
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

    /**
     * @dev Insert (or update) a token group for a given account and token ID
     * @param account The address of the account
     * @param id The ID of the token
     * @param amount The amount of tokens in the batch
     * @param expiresAt The expiration timestamp of the batch
     */
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

    /**
     * @dev Get a filtered array of token groups for a given account and token ID, without expired or empty groups
     * @param account The address to check
     * @param id The token ID to check
     * @return Array of Group structs, with amount and expiration of each batch
     */
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

/**
 * @title EVMAuth
 * @dev Implementation of EVMAuthExpiringERC1155 that provides a unified method for metadata management
 */
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

    /**
     * @dev Constructor
     * @param name Name of the EIP-712 signing domain
     * @param version Current major version of the EIP-712 signing domain
     * @param uri URI for ERC-1155 token metadata
     * @param delay Delay (in seconds) for transfer of contract ownership
     * @param owner Address of the contract owner
     */
    constructor(
        string memory name,
        string memory version,
        string memory uri,
        uint48 delay,
        address owner
    ) EVMAuthExpiringERC1155(name, version, uri, delay, owner) {}

    /**
     * @dev Get the metadata of a token
     * @param id The ID of the token to check
     * @return The metadata of the token, including price and TTL
     */
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

    /**
     * @dev Get the metadata of a batch of tokens
     * @param ids The IDs of the tokens to check
     * @return result The metadata of the tokens, including price and TTL
     */
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

    /**
     * @dev Set comprehensive metadata for a token
     * @param id The ID of the token
     * @param _active Whether the token is active
     * @param _burnable Whether the token is burnable
     * @param _transferable Whether the token is transferable
     * @param _price The price of the token (0 if not for sale)
     * @param _ttl The time-to-live in seconds (0 for non-expiring)
     */
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

    /**
     * @dev Sets a new URI for all token types, by relying on the token ID substitution mechanism
     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the ERC].
     *
     * By this mechanism, any occurrence of the `\{id\}` substring in either the URI or any of the values
     * in the JSON file at said URI will be replaced by clients with the token ID.
     *
     * For example, the `https://token-cdn-domain/\{id\}.json` URI would be interpreted by clients as
     * `https://token-cdn-domain/000000000000000000000000000000000000000000000000000000000004cce0.json`
     * for token ID 0x4cce0.
     * @param value The URI to set
     */
    function setURI(string memory value) external {
        require(
            hasRole(TOKEN_MANAGER_ROLE, _msgSender()),
            "Unauthorized token manager"
        );
        _setURI(value);
    }
}
