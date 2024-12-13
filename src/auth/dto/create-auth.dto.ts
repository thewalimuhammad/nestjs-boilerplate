import { IsNotEmpty, IsString } from 'class-validator';

export class CreateAuthDto {
  @IsNotEmpty()
  name?: string;

  @IsNotEmpty()
  email: string;
}
