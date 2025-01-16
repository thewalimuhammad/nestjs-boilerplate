import { IsEmail, IsNotEmpty } from 'class-validator';

export class UpdateEmailDto {
  @IsNotEmpty()
  @IsEmail()
  newEmail: string;

  @IsNotEmpty()
  password: string;
}
