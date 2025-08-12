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
exports.startOtpCleanup = void 0;
const otp_model_1 = __importDefault(require("../models/otp.model"));
const node_cron_1 = __importDefault(require("node-cron"));
// Run every 6 hours
const startOtpCleanup = () => {
    node_cron_1.default.schedule('0 */6 * * *', () => __awaiter(void 0, void 0, void 0, function* () {
        try {
            const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
            yield otp_model_1.default.deleteMany({
                $or: [{ isValid: false }, { expiresAt: { $lt: cutoff } }],
            });
            console.log('[Cleanup] Removed expired or invalid OTPs');
        }
        catch (error) {
            console.error('[Cleanup] Error during OTP cleanup:', error);
        }
    }));
};
exports.startOtpCleanup = startOtpCleanup;
