"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 21:
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
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(6);
const auth_service_1 = __webpack_require__(22);
const express_1 = __webpack_require__(24);
const login_dto_1 = __webpack_require__(25);
const jwt_access_guard_1 = __webpack_require__(26);
const users_service_1 = __webpack_require__(9);
const jwt_refresh_guard_1 = __webpack_require__(28);
const refreshToken_dto_1 = __webpack_require__(29);
const login_ex_filter_1 = __webpack_require__(49);
let AuthController = class AuthController {
    constructor(authService, userService) {
        this.authService = authService;
        this.userService = userService;
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
    async refresh(refreshTokenDto, res) {
        try {
            const newAccessToken = (await this.authService.refresh(refreshTokenDto)).accessToken;
            res.setHeader('Authorization', 'Bearer ' + newAccessToken);
            res.cookie('access_token', newAccessToken, {
                httpOnly: true,
            });
            res.send({ newAccessToken });
        }
        catch (err) {
            throw new common_1.UnauthorizedException('Invalid refresh-token');
        }
    }
    async user(req, res) {
        const userId = req.user.id;
        const verifiedUser = await this.userService.findUserById(userId);
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
    (0, common_1.UseFilters)(login_ex_filter_1.RateLimitFilter),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof login_dto_1.LoginDto !== "undefined" && login_dto_1.LoginDto) === "function" ? _c : Object, typeof (_d = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _d : Object]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('refresh'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_f = typeof refreshToken_dto_1.RefreshTokenDto !== "undefined" && refreshToken_dto_1.RefreshTokenDto) === "function" ? _f : Object, typeof (_g = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refresh", null);
__decorate([
    (0, common_1.Get)('authenticate'),
    (0, common_1.UseGuards)(jwt_access_guard_1.JwtAccessAuthGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_h = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _h : Object]),
    __metadata("design:returntype", typeof (_j = typeof Promise !== "undefined" && Promise) === "function" ? _j : Object)
], AuthController.prototype, "user", null);
__decorate([
    (0, common_1.Post)('logout'),
    (0, common_1.UseGuards)(jwt_refresh_guard_1.JwtRefreshGuard),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, typeof (_k = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _k : Object]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], AuthController.prototype, "logout", null);
AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object])
], AuthController);
exports.AuthController = AuthController;


/***/ }),

/***/ 49:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RateLimitFilter = void 0;
const common_1 = __webpack_require__(6);
const throttler_1 = __webpack_require__(35);
const class_validator_1 = __webpack_require__(18);
const exceptionTypes = [throttler_1.ThrottlerException, common_1.NotFoundException, common_1.BadRequestException, class_validator_1.ValidationError];
let RateLimitFilter = class RateLimitFilter {
    catch(exception, host) {
        const ctx = host.switchToHttp();
        const request = ctx.getRequest();
        const response = ctx.getResponse();
        const ex = handlingException(exception);
        response.status(ex.code).json({
            statusCode: ex.code,
            message: ex.message,
            timestamp: new Date().toISOString(),
            path: request.url,
        });
    }
};
RateLimitFilter = __decorate([
    (0, common_1.Catch)(...exceptionTypes)
], RateLimitFilter);
exports.RateLimitFilter = RateLimitFilter;
const handlingException = (err) => {
    if (err instanceof common_1.BadRequestException) {
        if (err instanceof class_validator_1.ValidationError) {
            return {
                code: 400, message: `Bad Request ${class_validator_1.ValidationError}`
            };
        }
        return {
            code: 400, message: "비밀번호 오류입니다."
        };
    }
    else if (err instanceof common_1.NotFoundException) {
        return {
            code: 404, message: "해당 이메일의 유저를 찾을 수 없습니다."
        };
    }
    else if (err instanceof throttler_1.ThrottlerException) {
        return {
            code: 429, message: "로그인 요청 허용횟수를 초과하였습니다. 15초후에 다시 시도하여주세요"
        };
    }
    else {
        return {
            code: 500, message: "알 수 없는 오류가 발생하였습니다."
        };
    }
};


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("92b001d208c0c4218f48")
/******/ })();
/******/ 
/******/ }
;