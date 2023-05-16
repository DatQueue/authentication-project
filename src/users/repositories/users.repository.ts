import { CustomRepository } from "src/common/repository-module/typeorm-ex.module";
import { Repository } from "typeorm";
import { User } from "../entities/users.entity";

@CustomRepository(User)
export class UsersRepository extends Repository<User> {}