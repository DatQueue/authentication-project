"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 3:
/***/ ((module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(4);
const app_module_1 = __webpack_require__(5);
const dotenv = __webpack_require__(33);
const common_1 = __webpack_require__(6);
const cookieParser = __webpack_require__(34);
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.setGlobalPrefix("api");
    app.useGlobalPipes(new common_1.ValidationPipe({ transform: true }));
    app.use(cookieParser());
    dotenv.config();
    await app.listen(4000, '0.0.0.0');
    if (true) {
        module.hot.accept();
        module.hot.dispose(() => app.close());
    }
}
bootstrap();


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("6d8df2b8d4a4c74793c4")
/******/ })();
/******/ 
/******/ }
;