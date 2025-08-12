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
const express_1 = __importDefault(require("express"));
const mongoose_1 = __importDefault(require("mongoose"));
const driver_routes_1 = __importDefault(require("../src/routes/driver.routes"));
const dotenv_1 = __importDefault(require("dotenv"));
const cleanup_1 = require("./utils/cleanup");
const category_routes_1 = __importDefault(require("../src/routes/category.routes"));
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use('/api/drivers', driver_routes_1.default);
app.use('/api', category_routes_1.default);
const startServer = () => __awaiter(void 0, void 0, void 0, function* () {
    try {
        yield mongoose_1.default.connect(process.env.MONGODB_URI_DRIVER ||
            'mongodb://localhost:27017/haulage-driver-service');
        (0, cleanup_1.startOtpCleanup)();
        console.log('Connected to MongoDB');
        // Drop problematic index
        yield mongoose_1.default
            .model('Driver')
            .collection.dropIndex('licenseNumber_1')
            .catch((err) => {
            if (err.codeName !== 'IndexNotFound')
                throw err;
        });
        // Ensure correct indexes
        yield mongoose_1.default.model('Driver').ensureIndexes();
        console.log('Indexes ensured');
        const PORT = process.env.PORT || 3002;
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    }
    catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
});
mongoose_1.default.set('debug', true);
startServer();
