import { PassportSerializer } from "@nestjs/passport";
import { Injectable } from "@nestjs/common";
import { User } from "../../../users/entities/users.entity";
import { GoogleAuthenticationService } from "../google-auth.service";

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(
    private readonly googleAuthService: GoogleAuthenticationService, 
  ) {
    super();
  }

  async serializeUser(user: User, done: (err: any, user?: any) => void): Promise<any> {
    console.log(user, "serializeUser");
    done(null, user);
  }

  async deserializeUser(payload: any, done: (err: any, user?: any) => void): Promise<any> {
    const user = await this.googleAuthService.findUserById(payload.id);
    console.log(user, "deserializeUser");
    return user ? done(null, user) : done(null, null);
  }
}