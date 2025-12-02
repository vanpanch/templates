// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IERC20, IERC4626, ERC20, ERC4626, Math, SafeERC20} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// IShareConfig.sol
interface IShareConfig {
    function share() external view returns (uint256);
}

interface IPartnerShareConfig is IShareConfig {
    function controller() external view returns (address);
}

// IChargeConfig.sol
interface IChargeConfig {
    function charge() external view returns (uint96);

    function setCharge(uint256 newCharge) external;
}

// IYieldVaultFactory.sol
interface IYieldVaultFactory is IShareConfig, IChargeConfig {
    /// @notice The underlying vault that YieldVault vaults uses.
    function UNDERLYING() external view returns (address);

    /// @notice The default YieldVault vault created with the factory. This vault does not have a referrer.
    function YIELD_VAULT() external view returns (address);

    /// @notice Tracks existing YieldVault contracts where the partner is sharing the charges.
    function partners(address) external view returns (address);

    /// @notice Tracks which YieldVault contract a user is depositing into.
    function userVaults(address) external view returns (address);

    /// @notice Sets the share to the introducer.
    function setShare(uint256 newShare) external;

    /// @notice Whether a YieldVault vault was created with the factory.
    function isYieldVault(address target) external view returns (bool);

    /// @notice Creates a new YieldVault vault with a introducer.
    function createYieldVault(
        address introducer,
        bytes32 salt
    ) external returns (IYieldVault yieldVault);

    /// @notice Sets the deposit vault for a user.
    function setUserVault(address vault) external;

    /// @notice Creates a new YieldVault vault with a introducer and deposits assets into it.
    function createAndDeposit(
        address introducer,
        bytes32 salt,
        uint256 assets
    ) external returns (IYieldVault yieldVault, uint256 shares);
}

// IYieldPartner.sol
interface IYieldPartner {
    /// @notice The address of the partner share config.
    function shareConfig() external view returns (IPartnerShareConfig);

    /// @notice The address of the partner receiving the earnings.
    function partner() external view returns (address);

    /// @notice The address of the vault that earnings are paid to on behalf of the controller.
    function controllerVault() external view returns (IERC4626);

    /// @notice The address of the vault that earnings are paid to on behalf of the partner.
    function distributionVault() external view returns (IERC4626);

    /// @notice Pays out the earnings to the controller and partner.
    /// @dev Callable by anyone to trigger payout of earnings for ease-of-operations.
    function distribute(IERC4626 vault) external;

    /// @notice Pays out an amount of earnings to the controller and partner for a given vault.
    /// @dev Callable by anyone to trigger payout of earnings for ease-of-operations.
    function distributeWithAmount(IERC4626 vault, uint256 amount) external;

    /// @notice Sets the distribution vault.
    function setDistributionVault(address vault) external;
}

// IYieldVault.sol
interface IBatchCall {
    function multicall(bytes[] calldata) external returns (bytes[] memory);
}

interface IYieldVaultBase {
    /// @notice The underlying vault contract
    function UNDERLYING() external view returns (IERC4626);

    /// @notice OpenZeppelin decimals offset used by the ERC4626 implementation
    function DECIMALS_OFFSET() external view returns (uint8);

    /// @notice The charge recipient
    function chargeReceiver() external view returns (address);

    /// @notice The treasury address, all ERC20 tokens on this contract will be sent to this address
    function treasury() external view returns (address);

    /// @notice The last total assets
    function lastTotalHoldings() external view returns (uint256);

    /// @notice Sets the charge recipient address
    function setChargeReceiver(address newChargeReceiver) external;

    /// @notice Sets the treasury address
    function setTreasury(address newTreasury) external;

    /// @notice Accrues the charge and mints charge shares to the charge recipient
    function accrueCharge() external;

    /// @notice Transfers ERC20 tokens to the treasury address
    function collect(address token) external;
}

/// @title IYieldVault
/// @author Send Squad
/// @notice ERC4626 vault interface allowing users to deposit assets to earn yield through an underlying vault
interface IYieldVault is
    IYieldVaultBase,
    IERC4626,
    IERC20Permit,
    IBatchCall,
    IChargeConfig
{
    // solhint-disable-previous-line no-empty-blocks
}

// IController.sol
interface IController {
    /// @notice The controller address
    function controller() external view returns (address);

    /// @notice Sets the controller address
    function setController(address newController) external;
}

// Utils.sol
/// @notice Library exposing helpers.
/// @dev Inspired by https://github.com/morpho-org/morpho-utils.
library Utils {
    /// @dev Returns the min of `x` and `y`.
    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        assembly {
            z := xor(x, mul(xor(x, y), lt(y, x)))
        }
    }

    /// @dev Returns max(0, x - y).
    function zeroFloorSub(
        uint256 x,
        uint256 y
    ) internal pure returns (uint256 z) {
        assembly {
            z := mul(gt(x, y), sub(x, y))
        }
    }
}

// Events.sol
library Events {
    /// @notice Emitted when charge is set to `newCharge`.
    event SetCharge(address indexed caller, uint256 newCharge);
    /// @notice Emitted when charge recipient is set to `newChargeReceiver`.
    event SetChargeReceiver(address indexed newChargeReceiver);
    /// @notice Emitted when treasury address is set to `newTreasury`.
    event SetTreasury(address indexed newTreasury);
    /// @notice Emitted when tokens are sent to the treasury address.
    event Collect(
        address indexed caller,
        address indexed token,
        uint256 amount
    );
    /// @notice Emitted when interest are accrued.
    event AccrueInterest(uint256 newTotalAssets, uint256 chargeShares);
    /// @notice Emitted when the last total assets is updated to `updatedTotalAssets`.
    event UpdateLastTotalAssets(uint256 updatedTotalAssets);
    /// @notice Emitted when the partner address is set to `newPartner`.
    event SetPartner(address indexed newPartner);
    /// @notice Emitted when the pending owner is set to `newOwner`.
    event OwnershipTransferStarted(
        address indexed previousOwner,
        address indexed newOwner
    );
    /// @notice Emitted when the controller address is set to `newController`.
    event SetController(address indexed newController);
    /// @notice Emitted when the YieldVault deposit address is set to `newDeposit` for sender.
    event SetUserVault(address indexed newDeposit);
    /// @notice Emitted when the partner pays out the earnings.
    event PartnerDistribute(
        address indexed caller,
        address indexed vault,
        address indexed asset,
        uint256 amount,
        uint256 controllerShare,
        uint256 partnerShare
    );
    /// @notice Emitted when a new YieldVault vault is created.
    event CreateYieldVault(
        address indexed yieldVault,
        address indexed caller,
        address initialOwner,
        address indexed vault,
        address chargeReceiver,
        address treasury,
        uint96 charge,
        bytes32 salt
    );
    /// @notice Emitted when the share is set to `newShare`.
    event SetShare(uint256 newShare);
    /// @notice Emitted when a new partner is created.
    event NewPartner(address partner, address sea);
    /// @notice Emitted when the distribution vault is set to `distributionVault`.
    event SetDistributionVault(address distributionVault);
}

// Errors.sol
/// @title Errors
/// @author Send Squad
/// @notice Errors for YieldVault
library Errors {
    /// @notice Thrown when the zero address is passed
    error ZeroAddress();
    /// @notice Thrown when a value is already set
    error AlreadySet();
    /// @notice Thrown when max charge is exceeded
    error MaxChargeExceeded();
    /// @notice Thrown when zero charge recipient is set
    error ZeroChargeRecipient();
    /// @notice Thrown when max share is exceeded
    error MaxShareExceeded();
    /// @notice Thrown when zero amount is passed
    error ZeroAmount();
    /// @notice Thrown when there is an asset mismatch
    error AssetMismatch();
    /// @notice Thrown when the sender is not the controller
    error UnauthorizedController();
    /// @notice Thrown when the sender is not the partner
    error UnauthorizedPartner();
    /// @notice Thrown when the address is not a YieldVault vault
    error NotYieldVaultVault();
}

// Constants.sol
uint256 constant WAD = 1e18;

library Constants {
    // @dev The maximum charge that can be set. (50%)
    uint256 internal constant MAX_CHARGE = 0.5e18;

    /// @notice the total basis points of the charge share between controller and partner
    uint256 public constant SHARE_TOTAL = WAD;
}

contract Queen {
    address queen;
    uint256 public prize;

    constructor() payable {
        queen = msg.sender;
        prize = msg.value;
    }

    receive() external payable {
        require(msg.value >= prize);
        payable(queen).transfer(msg.value);
        queen = msg.sender;
        prize = msg.value;
    }

    function getQueen() public view returns (address) {
        return queen;
    }
}

// Controller.sol
/**
 * @title Controller is an abstract contract that adds a way for a controller to ensure some functionality is only called by the controller.
 * @author Send Squad
 * @notice Controller is used to ensure that there is two tiered ownership of the contract where owners can perform some actions but not others.
 * @dev Contract module which provides access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 */
abstract contract Controller is IController, Ownable {
    /// @notice The controller address
    address private _controller;

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    constructor(address initialController) {
        if (initialController == address(0)) revert Errors.ZeroAddress();
        _setController(initialController);
    }

    /// @notice Only the controller can call this function
    /// @inheritdoc IController
    function setController(address newController) external onlyController {
        _setController(newController);
    }

    /* EXTERNAL */

    /**
     * @dev Returns the address of the controller.
     */
    function controller() public view virtual override returns (address) {
        return _controller;
    }

    /* INTERNAL */

    function _setController(address newController) internal {
        if (newController == controller()) revert Errors.AlreadySet();
        if (newController == address(0)) revert Errors.ZeroAddress();

        _controller = newController;

        emit Events.SetController(newController);
    }

    /* MODIFIERS */

    modifier onlyController() {
        if (_msgSender() != controller()) revert Errors.UnauthorizedController();
        _;
    }
}

// YieldVault.sol

/// @title YieldVault
/// @author Send Squad
/// @notice ERC4626 vault allowing users to deposit assets to earn yield through an underlying vault
contract YieldVault is
    ERC4626,
    ERC20Permit,
    Controller,
    IYieldVaultBase,
    Multicall,
    IChargeConfig
{
    using Math for uint256;
    using SafeERC20 for IERC20;
    using Utils for uint256;

    /* IMMUTABLES */

    /// @notice The underlying vault contract
    IERC4626 public immutable UNDERLYING;

    /// @notice OpenZeppelin decimals offset used by the ERC4626 implementation
    uint8 public immutable DECIMALS_OFFSET;

    /* STORAGE */

    /// @notice the current charge
    uint96 public override charge;

    /// @notice The charge recipient
    address public chargeReceiver;

    /// @notice The treasury address, all ERC20 tokens on this contract will be sent to this address
    address public treasury;

    /// @notice The last total assets
    uint256 public lastTotalHoldings;

    /* CONSTRUCTOR */

    constructor(
        address _controller,
        address owner,
        address vault,
        address asset,
        string memory _name,
        string memory _symbol,
        address _chargeReceiver,
        address _treasury,
        uint96 _charge
    )
        ERC4626(IERC20(asset))
        ERC20Permit(_name)
        ERC20(_name, _symbol)
        Controller(_controller)
        Ownable(owner)
    {
        if (vault == address(0)) revert Errors.ZeroAddress();
        if (_chargeReceiver != address(0)) chargeReceiver = _chargeReceiver;
        if (_treasury != address(0)) treasury = _treasury;
        if (_charge > Constants.MAX_CHARGE) revert Errors.MaxChargeExceeded();
        if (_charge != 0 && _chargeReceiver == address(0))
            revert Errors.ZeroChargeRecipient();

        charge = _charge;
        UNDERLYING = IERC4626(vault);
        DECIMALS_OFFSET = uint8(
            uint256(18).zeroFloorSub(IERC20Metadata(asset).decimals())
        );

        IERC20(asset).forceApprove(vault, type(uint256).max);
    }

    /* OWNER ONLY */

    /// @inheritdoc IChargeConfig
    function setCharge(uint256 newCharge) external onlyOwner {
        if (newCharge == charge) revert Errors.AlreadySet();
        if (newCharge > Constants.MAX_CHARGE) revert Errors.MaxChargeExceeded();
        if (newCharge != 0 && chargeReceiver == address(0))
            revert Errors.ZeroChargeRecipient();

        // Accrue charge using the previous charge set before changing it.
        accrueCharge();

        // Safe "unchecked" cast because newCharge <= MAX_CHARGE.
        charge = uint96(newCharge);

        emit Events.SetCharge(_msgSender(), charge);
    }

    /// @inheritdoc IYieldVaultBase
    function setChargeReceiver(address newChargeReceiver) external onlyOwner {
        if (newChargeReceiver == address(0)) revert Errors.ZeroAddress();
        chargeReceiver = newChargeReceiver;

        emit Events.SetChargeReceiver(newChargeReceiver);
    }

    /// @inheritdoc IYieldVaultBase
    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert Errors.ZeroAddress();
        treasury = newTreasury;

        emit Events.SetTreasury(newTreasury);
    }

    /* EXTERNAL */

    /// @inheritdoc IYieldVaultBase
    function collect(address token) external {
        if (treasury == address(0)) revert Errors.ZeroAddress();

        uint256 amount = IERC20(token).balanceOf(address(this));

        IERC20(token).safeTransfer(treasury, amount);

        emit Events.Collect(_msgSender(), token, amount);
    }

    /// @inheritdoc IYieldVaultBase
    function accrueCharge() public {
        _updateLastTotalHoldings(_accrueCharge());
    }

    /* ERC4626 (PUBLIC) */

    /// @inheritdoc IERC20Metadata
    function decimals() public view override(ERC20, ERC4626) returns (uint8) {
        return ERC4626.decimals();
    }

    /// @inheritdoc IERC4626
    /// @dev Warning: May be higher than the actual max deposit due to duplicate markets in the supplyQueue.
    function maxDeposit(address) public view override returns (uint256) {
        return _maxDeposit();
    }

    /// @inheritdoc IERC4626
    /// @dev Warning: May be higher than the actual max mint due to duplicate markets in the supplyQueue.
    function maxMint(address) public view override returns (uint256) {
        uint256 suppliable = _maxDeposit();

        return _convertToShares(suppliable, Math.Rounding.Floor);
    }

    /// @inheritdoc IERC4626
    /// @dev Warning: May be lower than the actual amount of assets that can be withdrawn by `owner` due to conversion
    /// roundings between shares and assets.
    function maxWithdraw(
        address owner
    ) public view override returns (uint256 assets) {
        (assets, , ) = _maxWithdraw(owner);
    }

    /// @inheritdoc IERC4626
    /// @dev Warning: May be lower than the actual amount of shares that can be redeemed by `owner` due to conversion
    /// roundings between shares and assets.
    function maxRedeem(address owner) public view override returns (uint256) {
        (
            uint256 assets,
            uint256 newTotalSupply,
            uint256 newTotalAssets
        ) = _maxWithdraw(owner);

        return
            _convertToSharesWithTotals(
                assets,
                newTotalSupply,
                newTotalAssets,
                Math.Rounding.Floor
            );
    }

    /// @inheritdoc IERC4626
    function deposit(
        uint256 assets,
        address receiver
    ) public override returns (uint256 shares) {
        uint256 newTotalAssets = _accrueCharge();

        // Update `lastTotalHoldings` to avoid an inconsistent state in a re-entrant context.
        // It is updated again in `_deposit`.
        lastTotalHoldings = newTotalAssets;

        shares = _convertToSharesWithTotals(
            assets,
            totalSupply(),
            newTotalAssets,
            Math.Rounding.Floor
        );

        _deposit(_msgSender(), receiver, assets, shares);
    }

    /// @inheritdoc IERC4626
    function mint(
        uint256 shares,
        address receiver
    ) public override returns (uint256 assets) {
        uint256 newTotalAssets = _accrueCharge();

        // Update `lastTotalHoldings` to avoid an inconsistent state in a re-entrant context.
        // It is updated again in `_deposit`.
        lastTotalHoldings = newTotalAssets;

        assets = _convertToAssetsWithTotals(
            shares,
            totalSupply(),
            newTotalAssets,
            Math.Rounding.Ceil
        );

        _deposit(_msgSender(), receiver, assets, shares);
    }

    /// @inheritdoc IERC4626
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public override returns (uint256 shares) {
        uint256 newTotalAssets = _accrueCharge();

        // Do not call expensive `maxWithdraw` and optimistically withdraw assets.

        shares = _convertToSharesWithTotals(
            assets,
            totalSupply(),
            newTotalAssets,
            Math.Rounding.Ceil
        );

        // `newTotalAssets - assets` may be a little off from `totalAssets()`.
        _updateLastTotalHoldings(newTotalAssets.zeroFloorSub(assets));

        _withdraw(_msgSender(), receiver, owner, assets, shares);
    }

    /// @inheritdoc IERC4626
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public override returns (uint256 assets) {
        uint256 newTotalAssets = _accrueCharge();

        // Do not call expensive `maxRedeem` and optimistically redeem shares.

        assets = _convertToAssetsWithTotals(
            shares,
            totalSupply(),
            newTotalAssets,
            Math.Rounding.Floor
        );

        // `newTotalAssets - assets` may be a little off from `totalAssets()`.
        _updateLastTotalHoldings(newTotalAssets.zeroFloorSub(assets));

        _withdraw(_msgSender(), receiver, owner, assets, shares);
    }

    /// @inheritdoc IERC4626
    function totalAssets() public view override returns (uint256 assets) {
        // Returns the total assets held in the underlying vault (with interest)
        assets = UNDERLYING.convertToAssets(UNDERLYING.balanceOf(address(this)));
    }

    /* ERC4626 (INTERNAL) */

    /// @inheritdoc ERC4626
    function _decimalsOffset() internal view override returns (uint8) {
        return DECIMALS_OFFSET;
    }

    /// @dev Returns the maximum amount of asset (`assets`) that the `owner` can withdraw from the vault, as well as the
    /// new vault's total supply (`newTotalSupply`) and total assets (`newTotalAssets`).
    function _maxWithdraw(
        address owner
    )
        internal
        view
        returns (uint256 assets, uint256 newTotalSupply, uint256 newTotalAssets)
    {
        uint256 chargeShares;
        (chargeShares, newTotalAssets) = _accruedChargeShares();
        newTotalSupply = totalSupply() + chargeShares;

        assets = _convertToAssetsWithTotals(
            balanceOf(owner),
            newTotalSupply,
            newTotalAssets,
            Math.Rounding.Floor
        );

        // can never withdraw more than the underlying vault can withdraw
        assets = Utils.min(assets, UNDERLYING.maxWithdraw(address(this)));
    }

    /// @dev Returns the maximum amount of assets that the vault can supply on the underlying vault.
    function _maxDeposit() internal view returns (uint256 totalSuppliable) {
        return UNDERLYING.maxDeposit(address(this));
    }

    /// @inheritdoc ERC4626
    /// @dev The accrual of performance charges is taken into account in the conversion.
    function _convertToShares(
        uint256 assets,
        Math.Rounding rounding
    ) internal view override returns (uint256) {
        (uint256 chargeShares, uint256 newTotalAssets) = _accruedChargeShares();
        return
            _convertToSharesWithTotals(
                assets,
                totalSupply() + chargeShares,
                newTotalAssets,
                rounding
            );
    }

    /// @inheritdoc ERC4626
    /// @dev The accrual of performance charges is taken into account in the conversion.
    function _convertToAssets(
        uint256 shares,
        Math.Rounding rounding
    ) internal view override returns (uint256) {
        (uint256 chargeShares, uint256 newTotalAssets) = _accruedChargeShares();
        return
            _convertToAssetsWithTotals(
                shares,
                totalSupply() + chargeShares,
                newTotalAssets,
                rounding
            );
    }

    /// @dev Returns the amount of shares that the vault would exchange for the amount of `assets` provided.
    /// @dev It assumes that the arguments `newTotalSupply` and `newTotalAssets` are up to date.
    function _convertToSharesWithTotals(
        uint256 assets,
        uint256 newTotalSupply,
        uint256 newTotalAssets,
        Math.Rounding rounding
    ) internal view returns (uint256) {
        return
            assets.mulDiv(
                newTotalSupply + 10 ** _decimalsOffset(),
                newTotalAssets + 1,
                rounding
            );
    }

    /// @dev Returns the amount of assets that the vault would exchange for the amount of `shares` provided.
    /// @dev It assumes that the arguments `newTotalSupply` and `newTotalAssets` are up to date.
    function _convertToAssetsWithTotals(
        uint256 shares,
        uint256 newTotalSupply,
        uint256 newTotalAssets,
        Math.Rounding rounding
    ) internal view returns (uint256) {
        return
            shares.mulDiv(
                newTotalAssets + 1,
                newTotalSupply + 10 ** _decimalsOffset(),
                rounding
            );
    }

    /// @inheritdoc ERC4626
    /// @dev Used in mint or deposit to deposit the underlying asset
    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal override {
        super._deposit(caller, receiver, assets, shares);

        UNDERLYING.deposit(assets, address(this));

        // `lastTotalHoldings + assets` may be a little off from `totalAssets()`.
        _updateLastTotalHoldings(lastTotalHoldings + assets);
    }

    /// @inheritdoc ERC4626
    /// @dev Used in redeem or withdraw to withdraw the underlying asset from the underlying vault.
    /// @dev Depending on 3 cases, reverts when withdrawing "too much" with:
    /// 1. NotEnoughLiquidity when withdrawing more than available liquidity.
    /// 2. ERC20InsufficientAllowance when withdrawing more than `caller`'s allowance.
    /// 3. ERC20InsufficientBalance when withdrawing more than `owner`'s balance.
    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal override {
        UNDERLYING.withdraw(assets, address(this), address(this));

        super._withdraw(caller, receiver, owner, assets, shares);
    }

    /* CHARGE MANAGEMENT */

    /// @dev Updates `lastTotalHoldings` to `updatedTotalAssets`.
    function _updateLastTotalHoldings(uint256 updatedTotalAssets) internal {
        lastTotalHoldings = updatedTotalAssets;

        emit Events.UpdateLastTotalAssets(updatedTotalAssets);
    }

    /// @dev Accrues the charge and mints the charge shares to the charge recipient.
    function _accrueCharge() internal returns (uint256 newTotalAssets) {
        uint256 chargeShares;
        (chargeShares, newTotalAssets) = _accruedChargeShares();

        if (chargeShares != 0) _mint(chargeReceiver, chargeShares);

        emit Events.AccrueInterest(newTotalAssets, chargeShares);
    }

    /// @dev Computes and returns the charge shares (`chargeShares`) to mint and the new vault's total assets
    /// (`newTotalAssets`).
    function _accruedChargeShares()
        internal
        view
        returns (uint256 chargeShares, uint256 newTotalAssets)
    {
        newTotalAssets = totalAssets();

        uint256 totalEarnings = newTotalAssets.zeroFloorSub(lastTotalHoldings);
        if (totalEarnings != 0 && charge != 0) {
            // It is acknowledged that `chargeAssets` may be rounded down to 0 if `totalEarnings * charge < WAD`.
            uint256 chargeAssets = totalEarnings.mulDiv(charge, WAD);
            // The charge assets is subtracted from the total assets in this calculation to compensate for the fact
            // that total assets is already increased by the total earnings (including the charge assets).
            chargeShares = _convertToSharesWithTotals(
                chargeAssets,
                totalSupply(),
                newTotalAssets - chargeAssets,
                Math.Rounding.Floor
            );
        }
    }
}

// YieldPartner.sol
/// @notice Partner contract for splitting earnings between controller and an partner.
contract YieldPartner is IYieldPartner {
    using SafeERC20 for IERC20;
    using Math for uint256;

    /* IMMUTABLES */

    /// @inheritdoc IYieldPartner
    IPartnerShareConfig public immutable override shareConfig;

    /// @inheritdoc IYieldPartner
    address public immutable override partner;

    /// @inheritdoc IYieldPartner
    IERC4626 public immutable override controllerVault;

    /* STATE */

    /// @inheritdoc IYieldPartner
    IERC4626 public override distributionVault;

    /* CONSTRUCTOR */

    constructor(
        address _partner,
        address _shareConfig,
        address _distributionVault,
        address _controllerVault
    ) {
        if (_partner == address(0)) revert Errors.ZeroAddress();
        if (_shareConfig == address(0)) revert Errors.ZeroAddress();
        if (_distributionVault == address(0)) revert Errors.ZeroAddress();
        if (_controllerVault == address(0)) revert Errors.ZeroAddress();
        partner = _partner;
        shareConfig = IPartnerShareConfig(_shareConfig);
        _setDistributionVault(_distributionVault);
        controllerVault = IERC4626(_controllerVault);
        if (controllerVault.asset() != distributionVault.asset())
            revert Errors.AssetMismatch();
    }

    /* EXTERNAL */

    /// @inheritdoc IYieldPartner
    function distribute(IERC4626 vault) external virtual {
        distributeWithAmount(vault, vault.maxRedeem(address(this)));
    }

    /// @inheritdoc IYieldPartner
    function distributeWithAmount(IERC4626 vault, uint256 amount) public virtual {
        IERC20 asset = IERC20(vault.asset());
        if (address(asset) != address(distributionVault.asset()))
            revert Errors.AssetMismatch();
        if (amount == 0) revert Errors.ZeroAmount();

        // convert to the underlying asset
        uint256 assets = vault.redeem(amount, address(this), address(this));

        // calculate the share
        uint256 share = shareConfig.share();
        uint256 controllerShare = assets.mulDiv(share, Constants.SHARE_TOTAL);
        uint256 partnerShare = assets.mulDiv(
            Constants.SHARE_TOTAL - share,
            Constants.SHARE_TOTAL
        );

        // transfer the share to the controller and partner
        controllerVault.deposit(controllerShare, shareConfig.controller());
        distributionVault.deposit(partnerShare, partner);

        emit Events.PartnerDistribute(
            msg.sender,
            address(vault),
            address(asset),
            assets,
            controllerShare,
            partnerShare
        );
    }

    /// @inheritdoc IYieldPartner
    function setDistributionVault(address vault) external onlyPartner {
        if (vault == address(0)) revert Errors.ZeroAddress();
        if (vault == address(distributionVault)) revert Errors.AlreadySet();

        IERC4626 newDistributionVault = IERC4626(vault);
        if (newDistributionVault.asset() != distributionVault.asset())
            revert Errors.AssetMismatch();

        _setDistributionVault(vault);
    }

    /* INTERNAL */

    modifier onlyPartner() {
        if (msg.sender != partner) revert Errors.UnauthorizedPartner();
        _;
    }

    function _setDistributionVault(address newDistributionVault) internal {
        distributionVault = IERC4626(newDistributionVault);

        IERC20 asset = IERC20(distributionVault.asset());
        asset.forceApprove(newDistributionVault, type(uint256).max);

        emit Events.SetDistributionVault(newDistributionVault);
    }
}

// YieldVaultFactory.sol
/// @title YieldVaultFactory
/// @author Send Squad
/// @custom:contact security@send.it
/// @notice This contract allows to create YieldVault vaults with a introducer and to index them easily.
contract YieldVaultFactory is IYieldVaultFactory, Controller {
    /* IMMUTABLES */

    IERC4626 private immutable _underlying;

    IYieldVault private immutable _defaultYieldVault;

    /* STORAGE */

    /// @inheritdoc IYieldVaultFactory
    mapping(address => bool) public isYieldVault;

    /// @inheritdoc IYieldVaultFactory
    mapping(address => address) public partners;

    /// @inheritdoc IYieldVaultFactory
    mapping(address => address) public userVaults;

    /// @inheritdoc IChargeConfig
    uint96 public override charge;

    /// @inheritdoc IShareConfig
    uint256 public share;

    /* CONSTRUCTOR */

    /// @dev Initializes the contract.
    constructor(
        address owner,
        address vault,
        address _controller,
        uint96 _charge,
        uint256 _share,
        bytes32 salt
    ) Controller(_controller) Ownable(owner) {
        if (vault == address(0)) revert Errors.ZeroAddress();
        if (_controller == address(0)) revert Errors.ZeroAddress();
        if (owner == address(0)) revert Errors.ZeroAddress();

        _underlying = IERC4626(vault);
        _setCharge(_charge);
        _setShare(_share);

        // create the default(no partner) yield vault contract
        IYieldVault yieldVault = _createYieldVault(controller(), salt);
        partners[address(0)] = address(yieldVault);
        _defaultYieldVault = yieldVault;
    }

    /* OWNER ONLY */

    /// @inheritdoc IChargeConfig
    function setCharge(uint256 newCharge) public onlyOwner {
        _setCharge(newCharge);
    }

    /// @inheritdoc IYieldVaultFactory
    function setShare(uint256 newShare) public onlyOwner {
        _setShare(newShare);
    }

    /* EXTERNAL */

    /// @inheritdoc IYieldVaultFactory
    function UNDERLYING() public view returns (address) {
        return address(_underlying);
    }

    /// @inheritdoc IYieldVaultFactory
    function YIELD_VAULT() external view returns (address) {
        return address(_defaultYieldVault);
    }

    /// @inheritdoc IYieldVaultFactory
    function createYieldVault(
        address introducer,
        bytes32 salt
    ) public returns (IYieldVault yieldVault) {
        if (partners[introducer] == address(0)) {
            // Use deposit vault of introducer as the distribution vault if it exists
            // otherwise partner will receive the default vault shares
            address distributionVault = userVaults[introducer] != address(0)
                ? userVaults[introducer]
                : address(_defaultYieldVault);

            // Create new partner vault
            YieldPartner partner = new YieldPartner{salt: salt}(
                introducer,
                address(this),
                distributionVault,
                address(_defaultYieldVault)
            );
            emit Events.NewPartner(introducer, address(partner));
            yieldVault = _createYieldVault(address(partner), salt);
            partners[introducer] = address(yieldVault);
        } else {
            // Use existing partner vault
            yieldVault = IYieldVault(partners[introducer]);
        }
    }

    /// @inheritdoc IYieldVaultFactory
    function setUserVault(address vault) public {
        _setUserVault(msg.sender, vault);
    }

    /// @inheritdoc IYieldVaultFactory
    function createAndDeposit(
        address introducer,
        bytes32 salt,
        uint256 assets
    ) external returns (IYieldVault yieldVault, uint256 shares) {
        yieldVault = createYieldVault(introducer, salt);

        // Transfer assets from user to this contract
        address asset = yieldVault.asset();
        IERC20(asset).transferFrom(msg.sender, address(this), assets);
        IERC20(asset).approve(address(yieldVault), assets);

        // Deposit assets into YieldVault on behalf of the user
        shares = yieldVault.deposit(assets, msg.sender);

        // Track deposit for user
        _setUserVault(msg.sender, address(yieldVault));
    }

    /* INTERNAL */

    function _createYieldVault(
        address chargeReceiver,
        bytes32 salt
    ) internal returns (IYieldVault yieldVault) {
        yieldVault = IYieldVault(
            address(
                new YieldVault{salt: salt}(
                    controller(),
                    owner(),
                    UNDERLYING(),
                    _underlying.asset(),
                    string.concat("Send Earn: ", _underlying.name()),
                    string.concat("se", _underlying.symbol()),
                    chargeReceiver,
                    controller(),
                    charge
                )
            )
        );

        isYieldVault[address(yieldVault)] = true;

        emit Events.CreateYieldVault(
            address(yieldVault),
            msg.sender,
            owner(),
            UNDERLYING(),
            chargeReceiver,
            controller(),
            charge,
            salt
        );
    }

    function _setCharge(uint256 newCharge) internal {
        if (newCharge == charge) revert Errors.AlreadySet();
        if (newCharge > Constants.MAX_CHARGE) revert Errors.MaxChargeExceeded();
        if (newCharge != 0 && controller() == address(0))
            revert Errors.ZeroChargeRecipient();

        // Safe "unchecked" cast because newCharge <= MAX_CHARGE.
        charge = uint96(newCharge);

        emit Events.SetCharge(_msgSender(), charge);
    }

    function _setShare(uint256 newShare) internal {
        if (newShare == share) revert Errors.AlreadySet();
        if (newShare > Constants.SHARE_TOTAL) revert Errors.MaxShareExceeded();

        share = newShare;

        emit Events.SetShare(newShare);
    }

    function _setUserVault(address depositor, address vault) internal {
        if (!isYieldVault[vault]) revert Errors.NotYieldVaultVault();
        if (userVaults[depositor] == vault) revert Errors.AlreadySet();
        userVaults[depositor] = vault;
        emit Events.SetUserVault(vault);
    }
}
