import { Repository } from "typeorm";
import { SocialLoginInfo } from "../entities/social-auth.entity";
import { CustomRepository } from "src/common/repository-module/typeorm-ex.module";

@CustomRepository(SocialLoginInfo)
export class SocialLoginInfoRepository extends Repository<SocialLoginInfo> {}