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
exports.confirmKyc = exports.getKyc = exports.submitKyc = exports.updateStatus = exports.updateProfile = exports.getProfile = exports.login = exports.getPendingDrivers = exports.resetPassword = exports.forgotPassword = exports.resendOtp = exports.confirmOtp = exports.register = exports.checkEmail = exports.verifyToken = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const driver_model_1 = __importDefault(require("../models/driver.model"));
const email_1 = require("../utils/email");
const otp_model_1 = __importDefault(require("../models/otp.model"));
const pendingDriver_model_1 = __importDefault(require("../models/pendingDriver.model"));
const generateOtp = () => {
    return Math.floor(1000 + Math.random() * 9000).toString();
};
const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    if (password.length < minLength) {
        return `Password must be at least ${minLength} characters`;
    }
    if (!hasUpperCase) {
        return 'Password must contain at least one uppercase letter';
    }
    if (!hasLowerCase) {
        return 'Password must contain at least one lowercase letter';
    }
    if (!hasNumber) {
        return 'Password must contain at least one number';
    }
    return null;
};
// Authentication middleware
const verifyToken = (req, res, next) => {
    var _a;
    const token = (_a = req.header('Authorization')) === null || _a === void 0 ? void 0 : _a.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({
            statusCode: '04',
            error: 'Access denied, no token provided',
        });
    }
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    }
    catch (error) {
        return res.status(401).json({
            statusCode: '04',
            error: 'Invalid or expired token',
        });
    }
};
exports.verifyToken = verifyToken;
const checkEmail = (email) => __awaiter(void 0, void 0, void 0, function* () {
    const driver = yield driver_model_1.default.findOne({ email });
    const pending = yield pendingDriver_model_1.default.findOne({ email });
    return {
        exists: !!(driver || pending),
        isDriver: !!driver,
    };
});
exports.checkEmail = checkEmail;
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { name, email, password, phone } = req.body;
        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({
                statusCode: '01',
                error: passwordError,
            });
        }
        const { exists, isDriver } = yield (0, exports.checkEmail)(email);
        if (isDriver) {
            return res.status(409).json({
                statusCode: '06',
                error: 'Email already registered',
            });
        }
        if (exists) {
            return res.status(409).json({
                statusCode: '02',
                message: 'Email awaiting confirmation, please verify OTP',
                email,
            });
        }
        const hashedPassword = yield bcryptjs_1.default.hash(password, 8);
        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        const lastSent = new Date();
        yield new pendingDriver_model_1.default({
            name,
            email,
            password: hashedPassword,
            phone,
            registrationStatus: 'unconfirmed',
        }).save();
        yield otp_model_1.default.create({
            email,
            otp,
            expiresAt,
            lastSent,
            isValid: true,
            purpose: 'registration',
        });
        yield (0, email_1.sendOtpEmail)(email, otp, 'Registration');
        res.status(200).json({
            statusCode: '00',
            message: 'OTP sent to email',
            email,
            purpose: 'registration',
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during OTP generation',
        });
    }
});
exports.register = register;
const confirmOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, otp } = req.body;
        const otpRecord = yield otp_model_1.default.findOne({ email, otp, isValid: true });
        if (!otpRecord) {
            return res.status(400).json({
                statusCode: '01',
                error: 'Invalid OTP',
            });
        }
        if (otpRecord.expiresAt < new Date()) {
            yield otp_model_1.default.updateOne({ _id: otpRecord._id }, { isValid: false });
            return res.status(400).json({
                statusCode: '01',
                error: 'OTP expired, please request a new one',
            });
        }
        if (otpRecord.purpose === 'registration') {
            const pendingDriver = yield pendingDriver_model_1.default.findOne({ email });
            if (!pendingDriver) {
                return res.status(404).json({
                    statusCode: '05',
                    error: 'Pending registration not found',
                });
            }
            const driver = new driver_model_1.default({
                name: pendingDriver.name,
                email,
                password: pendingDriver.password,
                phone: pendingDriver.phone,
                vehicleType: '',
                licenseNumber: '',
                status: 'pending',
                kycStatus: '',
            });
            yield driver.save();
            const token = jsonwebtoken_1.default.sign({ id: driver === null || driver === void 0 ? void 0 : driver._id, email }, process.env.JWT_SECRET, { expiresIn: '7d' });
            yield otp_model_1.default.deleteOne({ email });
            yield pendingDriver_model_1.default.deleteOne({ email });
            return res.status(201).json({
                statusCode: '00',
                message: 'Driver registered successfully',
                data: {
                    token,
                    driver: {
                        id: driver === null || driver === void 0 ? void 0 : driver._id,
                        name: driver.name,
                        email: driver.email,
                        phone: driver.phone,
                        status: driver.status,
                    },
                },
            });
        }
        else if (otpRecord.purpose === 'password_reset') {
            const driver = yield driver_model_1.default.findOne({ email });
            if (!driver) {
                return res.status(404).json({
                    statusCode: '05',
                    error: 'Driver not found',
                });
            }
            const resetToken = jsonwebtoken_1.default.sign({ id: driver._id, email }, process.env.JWT_SECRET, { expiresIn: '15m' });
            yield otp_model_1.default.deleteOne({ email });
            return res.status(200).json({
                statusCode: '00',
                message: 'OTP verified, proceed to reset password',
                data: { resetToken },
            });
        }
        else {
            return res.status(400).json({
                statusCode: '01',
                error: 'Invalid OTP purpose',
            });
        }
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during OTP confirmation',
        });
    }
});
exports.confirmOtp = confirmOtp;
const resendOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        const pendingDriver = yield pendingDriver_model_1.default.findOne({ email });
        if (!pendingDriver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'No pending registration found for this email',
            });
        }
        const otpRecord = yield otp_model_1.default.findOne({ email, isValid: true });
        if (otpRecord && otpRecord.expiresAt >= new Date()) {
            const timeSinceLastSent = (new Date().getTime() - otpRecord.lastSent.getTime()) / 1000;
            if (timeSinceLastSent < 60) {
                return res.status(429).json({
                    statusCode: '03',
                    error: 'Please wait before requesting another OTP',
                    resendIn: Math.ceil(60 - timeSinceLastSent),
                });
            }
        }
        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        const lastSent = new Date();
        yield otp_model_1.default.findOneAndUpdate({ email }, { email, otp, expiresAt, lastSent, isValid: true }, { upsert: true, new: true });
        yield (0, email_1.sendOtpEmail)(email, otp, 'completeOnboarding');
        res.status(200).json({
            statusCode: '00',
            message: 'New OTP sent to your email',
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during OTP resend',
        });
    }
});
exports.resendOtp = resendOtp;
const forgotPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        const { isDriver } = yield (0, exports.checkEmail)(email);
        if (!isDriver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'No registered driver found for this email',
            });
        }
        const otpRecord = yield otp_model_1.default.findOne({ email, isValid: true });
        if (otpRecord && otpRecord.expiresAt >= new Date()) {
            const timeSinceLastSent = (new Date().getTime() - otpRecord.lastSent.getTime()) / 1000;
            if (timeSinceLastSent < 60) {
                return res.status(429).json({
                    statusCode: '03',
                    error: 'Please wait before requesting another OTP',
                    resendIn: Math.ceil(60 - timeSinceLastSent),
                });
            }
        }
        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
        const lastSent = new Date();
        yield otp_model_1.default.findOneAndUpdate({ email }, {
            email,
            otp,
            expiresAt,
            lastSent,
            isValid: true,
            purpose: 'password_reset',
        }, { upsert: true, new: true });
        yield (0, email_1.sendOtpEmail)(email, otp, 'forgotPassword');
        res.status(200).json({
            statusCode: '00',
            message: 'OTP sent to your email for password reset',
            email,
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during password reset request',
        });
    }
});
exports.forgotPassword = forgotPassword;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { resetToken, newPassword } = req.body;
        const passwordError = validatePassword(newPassword);
        if (passwordError) {
            return res.status(400).json({
                statusCode: '01',
                error: passwordError,
            });
        }
        let decoded;
        try {
            decoded = jsonwebtoken_1.default.verify(resetToken, process.env.JWT_SECRET);
        }
        catch (error) {
            return res.status(401).json({
                statusCode: '04',
                error: 'Invalid or expired reset token',
            });
        }
        const driver = yield driver_model_1.default.findById(decoded.id);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        const hashedPassword = yield bcryptjs_1.default.hash(newPassword, 8);
        driver.password = hashedPassword;
        yield driver.save();
        res.status(200).json({
            statusCode: '00',
            message: 'Password reset successfully',
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during password reset',
        });
    }
});
exports.resetPassword = resetPassword;
const getPendingDrivers = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        if (req.role !== 'admin') {
            return res.status(403).json({
                statusCode: '04',
                error: 'Only admins can access pending drivers',
            });
        }
        const pendingDrivers = yield pendingDriver_model_1.default.find({
            registrationStatus: 'unconfirmed',
        }).select('name email phone createdAt');
        res.json({
            statusCode: '00',
            data: pendingDrivers,
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error fetching pending drivers',
        });
    }
});
exports.getPendingDrivers = getPendingDrivers;
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        const { exists, isDriver } = yield (0, exports.checkEmail)(email);
        const driver = yield driver_model_1.default.findOne({ email });
        if (!exists) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Invalid credentials',
            });
        }
        const pendingDriver = yield pendingDriver_model_1.default.findOne({ email });
        if (!isDriver && !pendingDriver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Invalid credentials. Please click on create new account button below',
            });
        }
        if (!isDriver && pendingDriver) {
            const otp = generateOtp();
            const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
            const lastSent = new Date();
            yield otp_model_1.default.findOneAndUpdate({ email }, { email, otp, expiresAt, lastSent, isValid: true }, { upsert: true, new: true });
            yield (0, email_1.sendOtpEmail)(email, otp, 'completeOnboarding');
            return res.status(400).json({
                statusCode: '02',
                message: 'New OTP sent to email, please confirm your email',
                email,
            });
        }
        if (isDriver) {
            if (!driver) {
                return res.status(404).json({
                    statusCode: '05',
                    error: 'Invalid credentials',
                });
            }
            const isMatch = yield bcryptjs_1.default.compare(password, driver.password);
            if (!isMatch) {
                return res.status(401).json({
                    statusCode: '04',
                    error: 'Invalid credentials. Please enter the right password, and try again',
                });
            }
            const token = jsonwebtoken_1.default.sign({ userId: driver._id, role: 'driver' }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
            return res.json({
                statusCode: '00',
                data: {
                    token,
                    driver: {
                        id: driver._id,
                        name: driver.name,
                        email: driver.email,
                        phone: driver.phone,
                        vehicleType: driver.vehicleType,
                        licenseNumber: driver.licenseNumber,
                        status: driver.status,
                        kycStatus: driver.kycStatus,
                    },
                },
            });
        }
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during login',
        });
    }
});
exports.login = login;
const getProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        if (!userId) {
            return res.status(401).json({
                statusCode: '04',
                error: 'User ID not found in token',
            });
        }
        const driver = yield driver_model_1.default.findById(userId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        return res.status(200).json({
            statusCode: '00',
            data: {
                id: driver._id,
                name: driver.name,
                email: driver.email,
                phone: driver.phone,
                status: driver.status,
                vehicleType: driver.vehicleType,
                licenseNumber: driver.licenseNumber,
                kycStatus: driver.kycStatus,
            },
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during profile retrieval',
        });
    }
});
exports.getProfile = getProfile;
const updateProfile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        if (!userId) {
            return res.status(401).json({
                statusCode: '04',
                error: 'User ID not found in token',
            });
        }
        const { name, phone, vehicleType, licenseNumber } = req.body;
        const driver = yield driver_model_1.default.findById(userId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        driver.name = name || driver.name;
        driver.phone = phone || driver.phone;
        driver.vehicleType = vehicleType || driver.vehicleType;
        driver.licenseNumber = licenseNumber || driver.licenseNumber;
        yield driver.save();
        return res.status(200).json({
            statusCode: '00',
            message: 'Profile updated successfully',
            data: {
                id: driver._id,
                name: driver.name,
                email: driver.email,
                phone: driver.phone,
                vehicleType: driver.vehicleType,
                licenseNumber: driver.licenseNumber,
                status: driver.status,
                kycStatus: driver.kycStatus,
            },
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during profile update',
        });
    }
});
exports.updateProfile = updateProfile;
const updateStatus = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { driverId, status } = req.body;
        const driver = yield driver_model_1.default.findById(driverId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        driver.status = status;
        yield driver.save();
        return res.status(200).json({
            statusCode: '00',
            message: 'Driver status updated successfully',
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during status update',
        });
    }
});
exports.updateStatus = updateStatus;
const submitKyc = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const driver = yield driver_model_1.default.findById(req.userId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        if (driver.kycStatus === 'processing' || driver.kycStatus === 'confirmed') {
            return res.status(400).json({
                statusCode: '01',
                error: 'KYC already submitted or approved',
            });
        }
        const { location, address, officeAddress, dateOfBirth, gender, selfie, driverLicensePicture, vehicleInformationPicture, vehicleInspectionDocumentPicture, daysOfAvailability, categories, } = req.body;
        driver.kycData = {
            location,
            address,
            officeAddress,
            dateOfBirth,
            gender,
            selfie,
            driversLicense: driverLicensePicture,
            vehicleInformation: vehicleInformationPicture,
            vehicleInspectionDocument: vehicleInspectionDocumentPicture,
            availabilityDays: daysOfAvailability,
            categories,
        };
        driver.kycStatus = 'processing';
        yield driver.save();
        return res.status(200).json({
            statusCode: '00',
            message: 'KYC submitted successfully, now processing',
            data: { kycStatus: driver.kycStatus, kycData: driver.kycData },
        });
    }
    catch (error) {
        res.status(500).json({
            statusCode: '01',
            error: 'Internal server error submitting KYC',
        });
    }
});
exports.submitKyc = submitKyc;
const getKyc = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        if (!userId) {
            return res.status(401).json({
                statusCode: '04',
                error: 'User ID not found in token',
            });
        }
        const driver = yield driver_model_1.default.findById(userId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        return res.status(200).json({
            statusCode: '00',
            data: {
                kycStatus: driver.kycStatus,
                kycData: driver.kycData || {
                    location: '',
                    address: '',
                    officeAddress: '',
                    dateOfBirth: '',
                    gender: '',
                    selfie: '',
                    driverLicensePicture: '',
                    vehicleInformationPicture: '',
                    vehicleInspectionDocumentPicture: '',
                    daysOfAvailability: [],
                    categories: [],
                },
            },
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during KYC retrieval',
        });
    }
});
exports.getKyc = getKyc;
const confirmKyc = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { driverId, kycStatus } = req.body;
        const driver = yield driver_model_1.default.findById(driverId);
        if (!driver) {
            return res.status(404).json({
                statusCode: '05',
                error: 'Driver not found',
            });
        }
        if (driver.kycStatus !== 'processing') {
            return res.status(400).json({
                statusCode: '01',
                error: 'KYC is not in processing state',
            });
        }
        driver.kycStatus = kycStatus;
        yield driver.save();
        return res.status(200).json({
            statusCode: '00',
            message: 'KYC status updated successfully',
            data: { kycStatus: driver.kycStatus },
        });
    }
    catch (error) {
        return res.status(500).json({
            statusCode: '01',
            error: 'Internal server error during KYC confirmation',
        });
    }
});
exports.confirmKyc = confirmKyc;
