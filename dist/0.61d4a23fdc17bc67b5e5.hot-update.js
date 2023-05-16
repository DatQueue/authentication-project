"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

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
const exceptionTypes = [throttler_1.ThrottlerException];
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
    if (err instanceof throttler_1.ThrottlerException) {
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
/******/ 	__webpack_require__.h = () => ("8ea5ea9f5950097759ac")
/******/ })();
/******/ 
/******/ }
;