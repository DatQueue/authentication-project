"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

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
const ip_module_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module './ips/ip.module'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
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
            ip_module_1.IpModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, users_service_1.UsersService, jwt_refresh_strategy_1.JwtRefreshStrategy, jwt_access_guard_1.JwtAccessAuthGuard, jwt_refresh_guard_1.JwtRefreshGuard],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ 14:
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
exports.User = void 0;
const ip_auth_user_entity_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module 'src/auth/ips/entities/ip-auth-user.entity'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
const typeorm_1 = __webpack_require__(13);
let User = class User {
};
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)(),
    __metadata("design:type", Number)
], User.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'firstname' }),
    __metadata("design:type", String)
], User.prototype, "firstName", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'lastname' }),
    __metadata("design:type", String)
], User.prototype, "lastName", void 0);
__decorate([
    (0, typeorm_1.Column)({ name: 'email' }),
    __metadata("design:type", String)
], User.prototype, "email", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], User.prototype, "password", void 0);
__decorate([
    (0, typeorm_1.Column)({ nullable: true }),
    __metadata("design:type", String)
], User.prototype, "currentRefreshToken", void 0);
__decorate([
    (0, typeorm_1.Column)({ type: 'datetime', nullable: true }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], User.prototype, "currentRefreshTokenExp", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => ip_auth_user_entity_1.IPAuthUser, ipAuthUser => ipAuthUser.ipAuth),
    __metadata("design:type", Array)
], User.prototype, "ipAuthUser", void 0);
User = __decorate([
    (0, typeorm_1.Entity)({ name: 'users' })
], User);
exports.User = User;


/***/ }),

/***/ 8:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const common_1 = __webpack_require__(6);
const users_service_1 = __webpack_require__(9);
const users_controller_1 = __webpack_require__(16);
const typeorm_1 = __webpack_require__(7);
const users_entity_1 = __webpack_require__(14);
const typeorm_ex_decorator_1 = __webpack_require__(19);
const users_repository_1 = __webpack_require__(11);
const ip_auth_user_entity_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module 'src/auth/ips/entities/ip-auth-user.entity'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
const ip_auth_entity_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module 'src/auth/ips/entities/ip-auth.entity'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
const ip_auth_repository_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module 'src/auth/ips/repositories/ip-auth.repository'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
const ip_auth_user_repository_1 = __webpack_require__(Object(function webpackMissingModule() { var e = new Error("Cannot find module 'src/auth/ips/repositories/ip-auth-user.repository'"); e.code = 'MODULE_NOT_FOUND'; throw e; }()));
let UsersModule = class UsersModule {
};
UsersModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([users_entity_1.User, ip_auth_entity_1.IPAuthentication, ip_auth_user_entity_1.IPAuthUser]),
            typeorm_ex_decorator_1.TypeOrmExModule.forCustomRepository([users_repository_1.UsersRepository, ip_auth_repository_1.IpAuthRepository, ip_auth_user_repository_1.IpAuthUserRepository]),
        ],
        providers: [users_service_1.UsersService],
        controllers: [users_controller_1.UsersController]
    })
], UsersModule);
exports.UsersModule = UsersModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("a54904433f7af190c52c")
/******/ })();
/******/ 
/******/ }
;