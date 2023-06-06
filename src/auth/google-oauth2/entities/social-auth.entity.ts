import { User } from "../../../users/entities/users.entity";
import { Column, Entity, ManyToOne, PrimaryColumn, PrimaryGeneratedColumn } from "typeorm";

@Entity({ name: 'social_login_info'})
export class SocialLoginInfo {
  
  @PrimaryColumn()
  id: string;

  @Column({ name: 'email'})
  email: string;

  @Column({ name: 'firstname'})
  firstName: string;

  @Column({ name: 'lastName' })
  lastName: string;

  @Column({ name: 'social_provider' })
  socialProvider: string;

  @Column({ name: 'external_id' })
  externalId: string;

  @Column({ name: 'access_token' })
  accessToken: string;

  @Column({ name: 'refresh_token' })
  refreshToken: string;
}