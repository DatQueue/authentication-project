import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Profile, Strategy, VerifyCallback } from "passport-google-oauth20";
import { GoogleAuthenticationService } from "../google-auth.service";
import { SocialLoginInfoDto } from "../utils/socialLogin-info.dto";


@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly googleAuthService: GoogleAuthenticationService
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: [process.env.GOOGLE_SCOPE_PROFILE, process.env.GOOGLE_SCOPE_EMAIL],
    });
  }

  authorizationParams(): {[key: string]: string; } {
    return ({
      access_type: 'offline',
      prompt: 'select_account',
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback): Promise<void> {
    console.log(accessToken);
    console.log(refreshToken);
    console.log(profile);
    const { name, emails, provider } = profile;
    const socialLoginUserInfo: SocialLoginInfoDto = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      socialProvider: provider,
      externalId: profile.id,
      accessToken,
      refreshToken,
    };
    try {
      const user = await this.googleAuthService.validateAndSaveUser(socialLoginUserInfo);
      console.log(user,"strategy");
      done(null, user, accessToken);
    } catch (err) {
      done(err, false);
    } 
  }
}