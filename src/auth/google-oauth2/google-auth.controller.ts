import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { GoogleAuthGuard } from "./guard/google-guard";

@Controller('auth/google')
export class GoogleAuthenticationController {
  constructor() {}

  @Get('/login')
  @UseGuards(GoogleAuthGuard)
  async handleLogin() {
    return {
      msg: 'Google Authentication',
    }
  }

  @Get('/redirect')
  @UseGuards(GoogleAuthGuard)
  async handleRedirect(
    @Req() req: any,
  ) {
    return req.user;
  }

  @Get('/status')
  async user(@Req() req: any) {
    if (req.user) {
      console.log(req.user, "Authenticated User");
      return {
        msg: "Authenticated",
      } 
    } else {
      console.log(req.user, "User cannot found");
      return {
        msg: "Not Authenticated",
      }
    }
  }
}