"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 30:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.APIRateLimitModule = void 0;
const common_1 = __webpack_require__(6);
const throttler_1 = __webpack_require__(35);
const test_controller_1 = __webpack_require__(49);
const test_service_1 = __webpack_require__(50);
const core_1 = __webpack_require__(4);
let APIRateLimitModule = class APIRateLimitModule {
};
APIRateLimitModule = __decorate([
    (0, common_1.Module)({
        imports: [
            throttler_1.ThrottlerModule.forRoot({
                ttl: 10,
                limit: 2,
            }),
        ],
        controllers: [test_controller_1.TestController],
        providers: [
            test_service_1.TestService,
            {
                provide: core_1.APP_GUARD,
                useClass: throttler_1.ThrottlerGuard,
            },
        ],
    })
], APIRateLimitModule);
exports.APIRateLimitModule = APIRateLimitModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("f5e093a96ada52f58217")
/******/ })();
/******/ 
/******/ }
;