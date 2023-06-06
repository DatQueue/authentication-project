import { Injectable } from "@nestjs/common";
import { SocialLoginInfoDto } from "./utils/socialLogin-info.dto";
import { UsersService } from "src/users/users.service";
import { Provider } from "./utils/provider.enum";
import { User } from "src/users/entities/users.entity";

@Injectable()
export class GoogleAuthenticationService {
  constructor(
    private readonly userService: UsersService,
  ) {}
  async validateAndSaveUser(socialLoginInfoDto: SocialLoginInfoDto): Promise<object | User> {
    const { email, refreshToken } = socialLoginInfoDto;
    console.log(refreshToken, "sdfsfsf")

    const existingUser = await this.userService.findUserByEmail(email);

    if (existingUser) {
      if (existingUser.socialProvider !== Provider.GOOGLE) {
        console.log(existingUser, "existingUser");
        return {
          existingUser: existingUser,
          msg: '해당 이메일을 사용중인 계정이 존재합니다.'
        }
      } else {
        const updateUserWithRefToken: User = await this.userService.updateSocialUserRefToken(existingUser.id, refreshToken);
        return updateUserWithRefToken;
      }
    }

    const newUser = await this.userService.createSocialUser(socialLoginInfoDto);
    const updateUser = await this.userService.updateSocialUserInfo(newUser.id);

    console.log(updateUser, "updateUser");
    return updateUser;
  }

  async findUserById(id: number) {
    const user = await this.userService.findUserById(id);
    return user;
  }
}