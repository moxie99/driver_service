"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const mongoose_1 = __importStar(require("mongoose"));
const DriverSchema = new mongoose_1.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    vehicleType: { type: String, default: '' },
    licenseNumber: { type: String, default: '' },
    status: {
        type: String,
        enum: ['pending', 'approved', 'suspended'],
        default: 'pending',
    },
    kycStatus: {
        type: String,
        enum: ['pending', 'processing', 'confirmed', 'rejected'],
        default: 'pending',
    },
    kycData: {
        location: { type: String },
        address: { type: String },
        officeAddress: { type: String },
        dateOfBirth: { type: Date },
        gender: { type: String, enum: ['male', 'female', 'other'] },
        selfie: { type: String },
        driversLicense: { type: String },
        vehicleInformation: { type: String },
        vehicleInspectionDocument: { type: String },
        availabilityDays: [
            {
                type: String,
                enum: [
                    'Monday',
                    'Tuesday',
                    'Wednesday',
                    'Thursday',
                    'Friday',
                    'Saturday',
                    'Sunday',
                ],
            },
        ],
        categories: {
            type: [String],
        },
    },
}, { timestamps: true });
// Remove existing index on licenseNumber if it exists
DriverSchema.index({ licenseNumber: 1 }, { unique: false, sparse: false });
// Ensure unique index on kyc.licenseNumber when set
DriverSchema.index({ 'kyc.licenseNumber': 1 }, { unique: true, sparse: true });
exports.default = mongoose_1.default.model('Driver', DriverSchema);
