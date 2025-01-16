import { Optional } from '@nestjs/common';
import { IsEmail, IsEnum, IsNotEmpty, Matches } from 'class-validator';
import { Role } from 'src/constant/index.constant';

export class UserSignUpDto {
  @Matches(/^(?=\S)(.{3,})$/, {
    message:
      'name must be at least 3 characters long and cannot be only spaces',
  })
  name: string;

  @IsEmail({}, { message: 'Invalid Email' })
  email: string;

  @IsEnum(Role, { message: 'role must be USER, ADMIN, SUPER_ADMIN' })
  role: Role;

  @Matches(
    /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    { message: 'Password too weak.' },
  )
  password: string;
}
