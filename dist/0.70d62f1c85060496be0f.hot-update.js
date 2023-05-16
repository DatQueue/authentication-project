"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 72:
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
var _a, _b, _c, _d, _e, _f, _g, _h;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TwoFactorAuthenticationController = void 0;
const users_service_1 = __webpack_require__(9);
const twoFactorAuthentication_service_1 = __webpack_require__(73);
const common_1 = __webpack_require__(6);
const express_1 = __webpack_require__(24);
const jwt_access_guard_1 = __webpack_require__(26);
const requestWithUser_interface_1 = __webpack_require__(146);
const twoFactorAuthentication_dto_1 = __webpack_require__(149);
const auth_service_1 = __webpack_require__(22);
let TwoFactorAuthenticationController = class TwoFactorAuthenticationController {
    constructor(twoFactorAuthenticationService, userService, authService) {
        this.twoFactorAuthenticationService = twoFactorAuthenticationService;
        this.userService = userService;
        this.authService = authService;
    }
    async register(res, request) {
        const { otpAuthUrl } = await this.twoFactorAuthenticationService.generateTwoFactorAuthenticationSecret(request.user);
        return await this.twoFactorAuthenticationService.pipeQrCodeStream(res, otpAuthUrl);
    }
    async turnOnTwoFactorAuthentication(req, twoFactorAuthenticationCodeDto) {
        const isCodeValidated = await this.twoFactorAuthenticationService.isTwoFactorAuthenticationCodeValid(twoFactorAuthenticationCodeDto.twoFactorAuthenticationCode, req.user);
        if (!isCodeValidated) {
            throw new common_1.UnauthorizedException('Invalid Authentication-Code');
        }
        await this.userService.turnOnTwoFactorAuthentication(req.user.id);
        return {
            msg: "TwoFactorAuthentication turned on"
        };
    }
    async authenticate(req, twoFactorAuthenticationCodeDto) {
        const isCodeValidated = await this.twoFactorAuthenticationService.isTwoFactorAuthenticationCodeValid(twoFactorAuthenticationCodeDto.twoFactorAuthenticationCode, req.user);
        if (!isCodeValidated) {
            throw new common_1.UnauthorizedException('Invalid Authentication-Code');
        }
        if (!req.user.isTwoFactorAuthenticationEnabled) {
            throw new common_1.ForbiddenException('Two-Factor Authentication is not enabled');
        }
        const accessToken = await this.authService.generateAccessToken(req.user, true);
        console.log(req.user.isSecondFactorAuthenticated);
        req.res.setHeader('Set-Cookie', [accessToken]);
        return req.user;
    }
};
__decorate([
    (0, common_1.Post)('generate'),
    (0, common_1.UseGuards)(jwt_access_guard_1.JwtAccessAuthGuard),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _d : Object, typeof (_e = typeof requestWithUser_interface_1.default !== "undefined" && requestWithUser_interface_1.default) === "function" ? _e : Object]),
    __metadata("design:returntype", Promise)
], TwoFactorAuthenticationController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('turn-on'),
    (0, common_1.UseGuards)(jwt_access_guard_1.JwtAccessAuthGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_f = typeof requestWithUser_interface_1.default !== "undefined" && requestWithUser_interface_1.default) === "function" ? _f : Object, typeof (_g = typeof twoFactorAuthentication_dto_1.TwoFactorAuthenticationCodeDto !== "undefined" && twoFactorAuthentication_dto_1.TwoFactorAuthenticationCodeDto) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], TwoFactorAuthenticationController.prototype, "turnOnTwoFactorAuthentication", null);
__decorate([
    (0, common_1.Post)('authenticate'),
    (0, common_1.UseGuards)(jwt_access_guard_1.JwtAccessAuthGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_h = typeof twoFactorAuthentication_dto_1.TwoFactorAuthenticationCodeDto !== "undefined" && twoFactorAuthentication_dto_1.TwoFactorAuthenticationCodeDto) === "function" ? _h : Object]),
    __metadata("design:returntype", Promise)
], TwoFactorAuthenticationController.prototype, "authenticate", null);
TwoFactorAuthenticationController = __decorate([
    (0, common_1.Controller)('2fa'),
    (0, common_1.UseInterceptors)(common_1.ClassSerializerInterceptor),
    __metadata("design:paramtypes", [typeof (_a = typeof twoFactorAuthentication_service_1.TwoFactorAuthenticationService !== "undefined" && twoFactorAuthentication_service_1.TwoFactorAuthenticationService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object, typeof (_c = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _c : Object])
], TwoFactorAuthenticationController);
exports.TwoFactorAuthenticationController = TwoFactorAuthenticationController;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("659b3d8ee82d7d0046ea")
/******/ })();
/******/ 
/******/ }
;