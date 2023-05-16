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
const jwt_access_strategy_1 = __webpack_require__(30);
const jwt_access_guard_1 = __webpack_require__(26);
const jwt_refresh_strategy_1 = __webpack_require__(32);
const jwt_refresh_guard_1 = __webpack_require__(28);
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
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, users_service_1.UsersService, jwt_access_strategy_1.JwtAccessStrategy, jwt_refresh_strategy_1.JwtRefreshStrategy, jwt_access_guard_1.JwtAccessAuthGuard, jwt_refresh_guard_1.JwtRefreshGuard],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ 30:
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
exports.JwtAccessStrategy = void 0;
const passport_1 = __webpack_require__(27);
const passport_jwt_1 = __webpack_require__(31);
const users_service_1 = __webpack_require__(9);
const common_1 = __webpack_require__(6);
const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['access_token'];
    }
    return token;
};
let JwtAccessStrategy = class JwtAccessStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-access-token') {
    constructor(userService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromExtractors([
                passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
                cookieExtractor,
            ]),
            secretOrKey: process.env.JWT_ACCESS_SECRET,
        });
        this.userService = userService;
    }
    async validate(payload) {
        const { id } = payload;
        const user = await this.userService.findUserById(id);
        if (!user) {
            throw new common_1.UnauthorizedException();
        }
        return user;
    }
};
JwtAccessStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], JwtAccessStrategy);
exports.JwtAccessStrategy = JwtAccessStrategy;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("93770c99c4afddc6755d")
/******/ })();
/******/ 
/******/ }
;