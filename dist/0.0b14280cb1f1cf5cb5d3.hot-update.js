"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 148:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const common_1 = __webpack_require__(6);
const passport_1 = __webpack_require__(27);
let JwtTwoFactorGuard = class JwtTwoFactorGuard extends (0, passport_1.AuthGuard)('jwt-two-factor') {
};
JwtTwoFactorGuard = __decorate([
    (0, common_1.Injectable)()
], JwtTwoFactorGuard);
exports["default"] = JwtTwoFactorGuard;


/***/ }),

/***/ 147:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtTwoFactorStrategy = void 0;
const common_1 = __webpack_require__(6);
const passport_1 = __webpack_require__(27);
const passport_jwt_1 = __webpack_require__(31);
const users_service_1 = __webpack_require__(9);
let JwtTwoFactorStrategy = class JwtTwoFactorStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-two-factor') {
    constructor(userService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([(req) => {
                    var _a;
                    return (_a = req === null || req === void 0 ? void 0 : req.cookies) === null || _a === void 0 ? void 0 : _a.access_token;
                }]),
            secretOrKey: process.env.JWT_ACCESS_SECRET
        });
        this.userService = userService;
    }
    async validate(payload) {
        const user = await this.userService.findUserById(payload.id);
        if (!user.isTwoFactorAuthenticationEnabled) {
            return user;
        }
        if (payload.isSecondFactorAuthenticated) {
            return user;
        }
    }
};
JwtTwoFactorStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], JwtTwoFactorStrategy);
exports.JwtTwoFactorStrategy = JwtTwoFactorStrategy;


/***/ }),

/***/ 20:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(6);
const auth_controller_1 = __webpack_require__(21);
const auth_service_1 = __webpack_require__(22);
const passport_1 = __webpack_require__(27);
const jwt_1 = __webpack_require__(23);
const config_1 = __webpack_require__(15);
const users_module_1 = __webpack_require__(8);
const users_service_1 = __webpack_require__(9);
const typeorm_1 = __webpack_require__(7);
const users_entity_1 = __webpack_require__(14);
const typeorm_ex_decorator_1 = __webpack_require__(19);
const users_repository_1 = __webpack_require__(11);
const jwt_access_guard_1 = __webpack_require__(26);
const jwt_refresh_strategy_1 = __webpack_require__(32);
const jwt_refresh_guard_1 = __webpack_require__(28);
const rate_limit_module_1 = __webpack_require__(30);
const twoFactorAuthentication_controller_1 = __webpack_require__(72);
const twoFactorAuthentication_service_1 = __webpack_require__(73);
const jwt_twoFactor_strategy_1 = __webpack_require__(147);
const jwt_twoFactor_guard_1 = __webpack_require__(148);
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([users_entity_1.User]),
            typeorm_ex_decorator_1.TypeOrmExModule.forCustomRepository([users_repository_1.UsersRepository]),
            passport_1.PassportModule.register({}),
            jwt_1.JwtModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: async (configService) => ({
                    secret: configService.get('JWT_ACCESS_SECRET'),
                    signOptions: {
                        expiresIn: configService.get('JWT_ACCESS_EXPIRATION_TIME'),
                    }
                }),
                inject: [config_1.ConfigService],
            }),
            (0, common_1.forwardRef)(() => users_module_1.UsersModule),
            rate_limit_module_1.APIRateLimitModule,
        ],
        controllers: [auth_controller_1.AuthController, twoFactorAuthentication_controller_1.TwoFactorAuthenticationController],
        providers: [auth_service_1.AuthService, users_service_1.UsersService, twoFactorAuthentication_service_1.TwoFactorAuthenticationService, jwt_refresh_strategy_1.JwtRefreshStrategy, jwt_twoFactor_strategy_1.JwtTwoFactorStrategy, jwt_access_guard_1.JwtAccessAuthGuard, jwt_refresh_guard_1.JwtRefreshGuard, jwt_twoFactor_guard_1.default],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("937a53d467f65d987a29")
/******/ })();
/******/ 
/******/ }
;