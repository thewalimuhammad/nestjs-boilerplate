import { MongooseModule } from '@nestjs/mongoose';
import { AuthSchema } from 'src/auth/entities/auth.entity';
import { UserSchema } from 'src/user/entities/user.entity';

export const mongooseFeatures = MongooseModule.forFeature([
  { name: 'Auth', schema: AuthSchema },
  { name: 'User', schema: UserSchema },
]);
