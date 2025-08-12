"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_validator_1 = require("express-validator");
const driver_controller_1 = require("../controllers/driver.controller");
const auth_middleware_1 = require("../middleware/auth.middleware");
const validate_middleware_1 = require("../middleware/validate.middleware");
const category_model_1 = __importDefault(require("../models/category.model"));
const router = (0, express_1.Router)();
router.post('/register', [
    (0, express_validator_1.body)('name').notEmpty().withMessage('Name is required'),
    (0, express_validator_1.body)('email').isEmail().withMessage('Invalid email format'),
    (0, express_validator_1.body)('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters'),
    (0, express_validator_1.body)('phone').notEmpty().withMessage('Phone number is required'),
], validate_middleware_1.validateRequest, driver_controller_1.register);
router.post('/confirm-otp', [
    (0, express_validator_1.body)('email').isEmail().withMessage('Invalid email format'),
    (0, express_validator_1.body)('otp')
        .isLength({ min: 4, max: 4 })
        .withMessage('OTP must be 4 digits'),
], validate_middleware_1.validateRequest, driver_controller_1.confirmOtp);
router.post('/resend-otp', [(0, express_validator_1.body)('email').isEmail().withMessage('Invalid email format')], validate_middleware_1.validateRequest, driver_controller_1.resendOtp);
router.post('/forgot-password', [(0, express_validator_1.body)('email').isEmail().withMessage('Invalid email format')], validate_middleware_1.validateRequest, driver_controller_1.forgotPassword);
router.post('/reset-password', [
    (0, express_validator_1.body)('resetToken').notEmpty().withMessage('Reset token is required'),
    (0, express_validator_1.body)('newPassword')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase letter')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase letter')
        .matches(/\d/)
        .withMessage('Password must contain at least one number'),
], validate_middleware_1.validateRequest, driver_controller_1.resetPassword);
router.get('/pending', auth_middleware_1.authenticate, driver_controller_1.getPendingDrivers);
router.post('/login', [
    (0, express_validator_1.body)('email').isEmail().withMessage('Invalid email format'),
    (0, express_validator_1.body)('password').notEmpty().withMessage('Password is required'),
], validate_middleware_1.validateRequest, driver_controller_1.login);
router.get('/profile', auth_middleware_1.authenticate, driver_controller_1.getProfile);
router.put('/profile', auth_middleware_1.authenticate, [
    (0, express_validator_1.body)('name').optional().notEmpty().withMessage('Name cannot be empty'),
    (0, express_validator_1.body)('phone')
        .optional()
        .notEmpty()
        .withMessage('Phone number cannot be empty'),
    (0, express_validator_1.body)('vehicleType')
        .optional()
        .notEmpty()
        .withMessage('Vehicle type cannot be empty'),
    (0, express_validator_1.body)('licenseNumber')
        .optional()
        .notEmpty()
        .withMessage('License number cannot be empty'),
], validate_middleware_1.validateRequest, driver_controller_1.updateProfile);
router.put('/status', auth_middleware_1.authenticate, [
    (0, express_validator_1.body)('driverId').notEmpty().withMessage('Driver ID is required'),
    (0, express_validator_1.body)('status')
        .isIn(['pending', 'approved', 'suspended'])
        .withMessage('Invalid status'),
], validate_middleware_1.validateRequest, driver_controller_1.updateStatus);
router.put('/kyc/confirm', auth_middleware_1.authenticate, [
    (0, express_validator_1.body)('driverId').notEmpty().withMessage('Driver ID is required'),
    (0, express_validator_1.body)('kycStatus')
        .isIn(['approved', 'rejected'])
        .withMessage('Invalid KYC status'),
], validate_middleware_1.validateRequest, driver_controller_1.confirmKyc);
router.post('/kyc', auth_middleware_1.authenticate, [
    (0, express_validator_1.body)('location').notEmpty().withMessage('Location is required'),
    (0, express_validator_1.body)('address').notEmpty().withMessage('Address is required'),
    (0, express_validator_1.body)('officeAddress').notEmpty().withMessage('Office address is required'),
    (0, express_validator_1.body)('dateOfBirth')
        .isISO8601()
        .toDate()
        .withMessage('Invalid date of birth format'),
    (0, express_validator_1.body)('gender')
        .isIn(['male', 'female', 'other'])
        .withMessage('Invalid gender'),
    (0, express_validator_1.body)('selfie').notEmpty().withMessage('Selfie is required'),
    (0, express_validator_1.body)('driversLicense').notEmpty().withMessage('Driver license is required'),
    (0, express_validator_1.body)('vehicleInformation')
        .notEmpty()
        .withMessage('Vehicle information is required'),
    (0, express_validator_1.body)('vehicleInspectionDocument')
        .notEmpty()
        .withMessage('Vehicle inspection document is required'),
    (0, express_validator_1.body)('availabilityDays')
        .isArray({ min: 1 })
        .withMessage('At least one availability day is required'),
    (0, express_validator_1.body)('availabilityDays.*')
        .isIn([
        'Monday',
        'Tuesday',
        'Wednesday',
        'Thursday',
        'Friday',
        'Saturday',
        'Sunday',
    ])
        .withMessage('Invalid availability day'),
    (0, express_validator_1.body)('categories')
        .isArray({ min: 1 })
        .withMessage('At least one category is required'),
    (0, express_validator_1.body)('categories.*').custom((value) => __awaiter(void 0, void 0, void 0, function* () {
        const category = yield category_model_1.default.findOne({ name: value });
        if (!category) {
            throw new Error(`Category ${value} does not exist`);
        }
        return true;
    })),
], validate_middleware_1.validateRequest, driver_controller_1.submitKyc);
router.get('/kyc', auth_middleware_1.authenticate, driver_controller_1.getKyc);
exports.default = router;
