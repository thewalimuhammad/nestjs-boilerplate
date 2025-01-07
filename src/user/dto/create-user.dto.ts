import { IsEmail, IsEnum, IsString } from 'class-validator';
import { Role } from 'src/constant/index.constant';

export class CreateUserDto {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsEnum(Role)
  role: Role;

  @IsString()
  password: string;
}
