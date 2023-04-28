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
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(6);
const auth_service_1 = __webpack_require__(21);
const express_1 = __webpack_require__(111);
const login_dto_1 = __webpack_require__(112);
const jwt_access_guard_1 = __webpack_require__(121);
const users_service_1 = __webpack_require__(9);
const jwt_refresh_guard_1 = __webpack_require__(126);
const refreshToken_dto_1 = __webpack_require__(127);
const jwt_1 = __webpack_require__(50);
let AuthController = class AuthController {
    constructor(authService, userService, jwtService) {
        this.authService = authService;
        this.userService = userService;
        this.jwtService = jwtService;
    }
    async login(loginDto, res) {
        const user = await this.authService.validateUser(loginDto);
        const access_token = await this.authService.generateAccessToken(user);
        const refresh_token = await this.authService.generateRefreshToken(user);
        await this.userService.setCurrentRefreshToken(refresh_token, user.id);
        res.setHeader('Authorization', 'Bearer ' + [access_token, refresh_token]);
        res.cookie('access_token', access_token, {
            httpOnly: true,
        });
        res.cookie('refresh_token', refresh_token, {
            httpOnly: true,
        });
        return {
            message: 'login success',
            access_token: access_token,
            refresh_token: refresh_token,
        };
    }
    async refresh(refreshTokenDto) {
        try {
            return await this.authService.refresh(refreshTokenDto);
        }
        catch (err) {
            throw new common_1.UnauthorizedException('Invalid refresh-token');
        }
    }
    async user(req, res) {
        const userId = await this.authService.userId(req);
        const verifiedUser = await this.userService.findUserById(userId);
        let access_token = req.cookies['access_token'];
        const refresh_token = req.cookies['refresh_token'];
        const expirationTime = access_token.exp;
        const currentTime = Math.floor(Date.now() / 1000);
        if (expirationTime < currentTime) {
            access_token = (await this.authService.refresh(refresh_token)).accessToken;
            res.setHeader('Authorization', 'Bearer ' + access_token);
            return res.send(verifiedUser);
        }
        return res.send(verifiedUser);
    }
    async logout(req, res) {
        await this.userService.removeRefreshToken(req.user.id);
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        return res.send({
            message: 'logout success'
        });
    }
};
__decorate([
    (0, common_1.Post)('login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof login_dto_1.LoginDto !== "undefined" && login_dto_1.LoginDto) === "function" ? _d : Object, typeof (_e = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _e : Object]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('refresh'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_g = typeof refreshToken_dto_1.RefreshTokenDto !== "undefined" && refreshToken_dto_1.RefreshTokenDto) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refresh", null);
__decorate([
    (0, common_1.Get)('authenticate'),
    (0, common_1.UseGuards)(jwt_access_guard_1.JwtAccessAuthGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_h = typeof express_1.Request !== "undefined" && express_1.Request) === "function" ? _h : Object, typeof (_j = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _j : Object]),
    __metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], AuthController.prototype, "user", null);
__decorate([
    (0, common_1.Post)('logout'),
    (0, common_1.UseGuards)(jwt_refresh_guard_1.JwtRefreshGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_l = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _l : Object]),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], AuthController.prototype, "logout", null);
AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object, typeof (_c = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _c : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("f10f198002eb05620a12")
/******/ })();
/******/ 
/******/ }
;