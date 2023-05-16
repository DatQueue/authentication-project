import { ArgumentsHost, Catch, ExceptionFilter } from "@nestjs/common";
import { ThrottlerException } from "@nestjs/throttler";

const exceptionTypes = [ThrottlerException];

@Catch(...exceptionTypes)
export class RateLimitFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest();
    const response = ctx.getResponse();

    const ex = handlingException(exception);

    response.status(ex.code).json({
      statusCode: ex.code,
      message: ex.message,
      timestamp: new Date().toISOString(),
      path: request.url,
    })
  }
}

interface ExceptionStatus {
  code: number;
  message: string;
}

const handlingException = (err: Error): ExceptionStatus => {
  if (err instanceof ThrottlerException) {
    return {
      code: 429, message: "로그인 요청 허용횟수를 초과하였습니다. 15초후에 다시 시도하여주세요"
    } 
  } else {
    return {
      code: 500, message: "알 수 없는 오류가 발생하였습니다."
    }
  }
}