import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { mongooseFeatures } from 'src/config/mongoose-features.config';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [mongooseFeatures, forwardRef(() => AuthModule)],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
