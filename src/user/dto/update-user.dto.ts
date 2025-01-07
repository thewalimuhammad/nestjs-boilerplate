import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import { IsOptional } from 'class-validator';
import { Role } from 'src/constant/index.constant';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsOptional()
  name: string;

  @IsOptional()
  email: string;

  @IsOptional()
  role: Role;

  @IsOptional()
  password: string;
}
