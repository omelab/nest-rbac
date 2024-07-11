# creating a NestJS project with TypeORM, PostgreSQL, and a role-based access control (RBAC) system.

## Prerequisites

Ensure you have the following installed:

- Node.js and npm
- PostgreSQL

### Step 1: Create a new NestJS project

1. Install the NestJS CLI if you haven't already:

```bash
npm install -g @nestjs/cli
```

2. Create a new project:

```bash
nest new project-name
```

3. Navigate to the project directory:

```bash
cd project-name
```

### Step 2: Install TypeORM and PostgreSQL

1. Install TypeORM and the PostgreSQL driver:

```bash
npm install @nestjs/typeorm typeorm pg
```

### Step 3: Set up TypeORM

1. Create a database module:

```bash
nest generate module database
```

2. Configure TypeORM in database.module.ts:

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { ConfigModule, ConfigService } from "@nestjs/config";

@Module({
  imports: [
    ConfigModule.forRoot(),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: "postgres",
        host: configService.get("DB_HOST"),
        port: +configService.get<number>("DB_PORT"),
        username: configService.get("DB_USERNAME"),
        password: configService.get("DB_PASSWORD"),
        database: configService.get("DB_NAME"),
        entities: [__dirname + "/../**/*.entity{.ts,.js}"],
        synchronize: true,
      }),
      inject: [ConfigService],
    }),
  ],
})
export class DatabaseModule {}
```

3. Add environment variables to .env:

```plaintext
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=your-username
DB_PASSWORD=your-password
DB_NAME=your-database
```

### Step 4: Create User and Role entities

1. Generate the user and role modules:

```bash
nest generate module user
nest generate service user
nest generate controller user
nest generate module role
nest generate service role
nest generate controller role
```

Define the User entity in user.entity.ts: 2. Define the User entity in user.entity.ts:

```ts
import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToMany,
  JoinTable,
} from "typeorm";
import { Role } from "../role/role.entity";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password: string;

  @ManyToMany(() => Role)
  @JoinTable()
  roles: Role[];
}
```

3. Define the Role entity in `role.entity.ts`:

```ts
import { Entity, Column, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;
}
```

4. Register the entities in their respective modules: `user.module.ts`:

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { User } from "./user.entity";
import { UserService } from "./user.service";
import { UserController } from "./user.controller";

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService],
  controllers: [UserController],
})
export class UserModule {}
```

`role.module.ts:`

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { Role } from "./role.entity";
import { RoleService } from "./role.service";
import { RoleController } from "./role.controller";

@Module({
  imports: [TypeOrmModule.forFeature([Role])],
  providers: [RoleService],
  controllers: [RoleController],
})
export class RoleModule {}
```

### Step 5: Implement Role-Based Access Control

1. Create a `roles.guard.ts` file to define the roles guard:

```ts
import { Injectable, CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable } from "rxjs";
import { User } from "../user/user.entity";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(
    context: ExecutionContext
  ): boolean | Promise<boolean> | Observable<boolean> {
    const roles = this.reflector.get<string[]>("roles", context.getHandler());
    if (!roles) {
      return true;
    }
    const request = context.switchToHttp().getRequest();
    const user: User = request.user;
    return (
      user && user.roles && user.roles.some((role) => roles.includes(role.name))
    );
  }
}
```

2.Create a `roles.decorator.ts` file to define the roles decorator:

```ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
```

3. Apply the guard and decorator in your controller:

```ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import { RolesGuard } from "./roles.guard";
import { Roles } from "./roles.decorator";

@Controller("some-resource")
@UseGuards(RolesGuard)
export class SomeResourceController {
  @Get()
  @Roles("admin")
  findAll() {
    // Only accessible by users with the 'admin' role
  }
}
```

### Step 6: Handle Authentication

For a complete system, you would typically integrate a more comprehensive authentication system using libraries like Passport. Here’s a simplified version:

1. Install Passport and JWT:

```bash
npm install @nestjs/passport passport passport-local passport-jwt @nestjs/jwt

```

2. Configure authentication using Passport and JWT, integrating it with your users and roles.

# Create a package similar to laravel-permission for NestJS.

## Step 1: Set Up a New NestJS Project

1. Install the NestJS CLI if you haven't already:

```bash
npm install -g @nestjs/cli
```

2. Create a new NestJS project:

```bash
nest new nest-permission
cd nest-permission
```

## Step 2: Install Required Packages

1. Install TypeORM and PostgreSQL (or your preferred database):

```bash
npm install @nestjs/typeorm typeorm pg
```

2. Install additional packages:

```bash
npm install @nestjs/passport passport passport-local passport-jwt @nestjs/jwt
```

## Step 3: Define User, Role, and Permission Entities

1. Create User, Role, and Permission entities: `src/user/user.entity.ts`:

```ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToMany,
  JoinTable,
} from "typeorm";
import { Role } from "../role/role.entity";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password: string;

  @ManyToMany(() => Role)
  @JoinTable()
  roles: Role[];
}
```

`src/role/role.entity.ts`:

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Permission } from "../permission/permission.entity";
import { User } from "../user/user.entity";

@Entity()
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Permission, (permission) => permission.roles)
  permissions: Permission[];

  @ManyToMany(() => User, (user) => user.roles)
  users: User[];
}
```

`src/permission/permission.entity.ts`:

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Role } from "../role/role.entity";

@Entity()
export class Permission {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}
```

## Step 4: Set Up TypeORM

1. Configure TypeORM in `app.module.ts`:

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { ConfigModule } from "@nestjs/config";
import { User } from "./user/user.entity";
import { Role } from "./role/role.entity";
import { Permission } from "./permission/permission.entity";

@Module({
  imports: [
    ConfigModule.forRoot(),
    TypeOrmModule.forRoot({
      type: "postgres",
      host: process.env.DB_HOST,
      port: +process.env.DB_PORT,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [User, Role, Permission],
      synchronize: true,
    }),
    TypeOrmModule.forFeature([User, Role, Permission]),
  ],
})
export class AppModule {}
```

## Step 5: Create Services and Controllers

1. Create services for User, Role, and Permission:`src/user/user.service.ts`:

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./user.entity";

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ) {}

  findAll(): Promise<User[]> {
    return this.userRepository.find({
      relations: ["roles", "roles.permissions"],
    });
  }

  findOne(id: number): Promise<User> {
    return this.userRepository.findOne(id, {
      relations: ["roles", "roles.permissions"],
    });
  }

  // Additional methods for creating, updating, and deleting users
}
```

`src/role/role.service.ts:`

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Role } from "./role.entity";

@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>
  ) {}

  findAll(): Promise<Role[]> {
    return this.roleRepository.find({ relations: ["permissions"] });
  }

  findOne(id: number): Promise<Role> {
    return this.roleRepository.findOne(id, { relations: ["permissions"] });
  }

  // Additional methods for creating, updating, and deleting roles
}
```

`src/permission/permission.service.ts`:

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Permission } from "./permission.entity";

@Injectable()
export class PermissionService {
  constructor(
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>
  ) {}

  findAll(): Promise<Permission[]> {
    return this.permissionRepository.find();
  }

  findOne(id: number): Promise<Permission> {
    return this.permissionRepository.findOne(id);
  }

  // Additional methods for creating, updating, and deleting permissions
}
```

2. Create controllers for User, Role, and Permission:

`src/user/user.controller.ts`:

```ts
import { Controller, Get, Param } from "@nestjs/common";
import { UserService } from "./user.service";

@Controller("users")
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @Get(":id")
  findOne(@Param("id") id: number) {
    return this.userService.findOne(id);
  }
}
```

`src/role/role.controller.ts`:

```ts
import { Controller, Get, Param } from "@nestjs/common";
import { RoleService } from "./role.service";

@Controller("roles")
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Get()
  findAll() {
    return this.roleService.findAll();
  }

  @Get(":id")
  findOne(@Param("id") id: number) {
    return this.roleService.findOne(id);
  }
}
```

`src/permission/permission.controller.ts:`

```ts
import { Controller, Get, Param } from "@nestjs/common";
import { PermissionService } from "./permission.service";

@Controller("permissions")
export class PermissionController {
  constructor(private readonly permissionService: PermissionService) {}

  @Get()
  findAll() {
    return this.permissionService.findAll();
  }

  @Get(":id")
  findOne(@Param("id") id: number) {
    return this.permissionService.findOne(id);
  }
}
```

## Step 6: Implement Role-Based Access Control

1. Create a guard to check roles and permissions:

`src/common/guards/roles.guard.ts`:

```ts
import { Injectable, CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Observable } from "rxjs";
import { UserService } from "../../user/user.service";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private userService: UserService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>("roles", context.getHandler());
    const permissions = this.reflector.get<string[]>(
      "permissions",
      context.getHandler()
    );
    if (!roles && !permissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = await this.userService.findOne(request.user.id);

    if (roles) {
      const hasRole = () =>
        user.roles.some((role) => !!roles.find((item) => item === role.name));
      if (!hasRole()) {
        return false;
      }
    }

    if (permissions) {
      const hasPermission = () =>
        user.roles.some((role) =>
          role.permissions.some(
            (permission) =>
              !!permissions.find((item) => item === permission.name)
          )
        );
      if (!hasPermission()) {
        return false;
      }
    }

    return true;
  }
}
```

2. Create decorators for roles and permissions:

`src/common/decorators/roles.decorator.ts`:

```ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
```

`src/common/decorators/permissions.decorator.ts`

```ts
import { SetMetadata } from "@nestjs/common";

export const Permissions = (...permissions: string[]) =>
  SetMetadata("permissions", permissions);
```

3. Apply the guard and decorators to your routes:

```ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import { RolesGuard } from "./common/guards/roles.guard";
import { Roles } from "./common/decorators/roles.decorator";
import { Permissions } from "./common/decorators/permissions.decorator";

@Controller("protected")
@UseGuards(RolesGuard)
export class ProtectedController {
  @Get("admin")
  @Roles("admin")
  getAdmin() {
    return "Admin content";
  }

  @Get("edit")
  @Permissions("edit articles")
  getEdit() {
    return "Edit content";
  }
}
```

## Step 7: Authentication (JWT Example)

1. Set up JWT authentication: `src/auth/auth.module.ts`

```ts
import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { JwtStrategy } from "./jwt.strategy";
import { UserService } from "../user/user.service";

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: "60m" },
    }),
  ],
  providers: [JwtStrategy, UserService],
})
export class AuthModule {}
```

`src/auth/jwt.strategy.ts`

```ts
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UserService } from "../user/user.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private userService: UserService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }
}
```

2. Protect routes using JWT:

```ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Controller("protected")
@UseGuards(AuthGuard("jwt"))
export class ProtectedController {
  @Get()
  getProtected() {
    return "Protected content";
  }
}
```

# Create a NestJS package for role-based access control (RBAC) and publish it to npm. Here's a detailed guide on how to create such a package and publish it.

## Step 1: Set Up Your Package

1. Create a new directory for your package:

```bash
mkdir nestjs-rbac
cd nestjs-rbac
```

2. Initialize a new npm package:

```bash
npm init -y
```

3. Install NestJS and TypeORM dependencies:

```bash
npm install @nestjs/common @nestjs/core @nestjs/typeorm typeorm pg
```

## Step 2: Create the Package Structure

1. Create the necessary directories and files:

```bash
mkdir src
touch src/index.ts
```

2. Define the package structure:

```bash
nestjs-rbac/
├── src/
│   ├── decorators/
│   │   ├── permissions.decorator.ts
│   │   ├── roles.decorator.ts
│   ├── entities/
│   │   ├── permission.entity.ts
│   │   ├── role.entity.ts
│   │   ├── user.entity.ts
│   ├── guards/
│   │   ├── roles.guard.ts
│   ├── services/
│   │   ├── permission.service.ts
│   │   ├── role.service.ts
│   │   ├── user.service.ts
│   ├── index.ts
├── package.json
```

## Step 3: Implement the Package

1. Create the entities:

`src/entities/user.entity.ts`

```ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToMany,
  JoinTable,
} from "typeorm";
import { Role } from "./role.entity";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password: string;

  @ManyToMany(() => Role)
  @JoinTable()
  roles: Role[];
}
```

`src/entities/role.entity.ts`

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Permission } from "./permission.entity";
import { User } from "./user.entity";

@Entity()
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Permission, (permission) => permission.roles)
  permissions: Permission[];

  @ManyToMany(() => User, (user) => user.roles)
  users: User[];
}
```

`src/entities/permission.entity.ts`

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Role } from "./role.entity";

@Entity()
export class Permission {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}
```

2. Create the services: `src/services/user.service.ts`

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "../entities/user.entity";

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ) {}

  findAll(): Promise<User[]> {
    return this.userRepository.find({
      relations: ["roles", "roles.permissions"],
    });
  }

  findOne(id: number): Promise<User> {
    return this.userRepository.findOne(id, {
      relations: ["roles", "roles.permissions"],
    });
  }

  // Additional methods for creating, updating, and deleting users
}
```

`src/services/role.service.ts:`

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Role } from "../entities/role.entity";

@Injectable()
export class RoleService {
  constructor(
    @InjectRepository(Role)
    private readonly roleRepository: Repository<Role>
  ) {}

  findAll(): Promise<Role[]> {
    return this.roleRepository.find({ relations: ["permissions"] });
  }

  findOne(id: number): Promise<Role> {
    return this.roleRepository.findOne(id, { relations: ["permissions"] });
  }

  // Additional methods for creating, updating, and deleting roles
}
```

`src/services/permission.service.ts`

```ts
import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { Permission } from "../entities/permission.entity";

@Injectable()
export class PermissionService {
  constructor(
    @InjectRepository(Permission)
    private readonly permissionRepository: Repository<Permission>
  ) {}

  findAll(): Promise<Permission[]> {
    return this.permissionRepository.find();
  }

  findOne(id: number): Promise<Permission> {
    return this.permissionRepository.findOne(id);
  }

  // Additional methods for creating, updating, and deleting permissions
}
```

3. Create the guards and decorators: `src/guards/roles.guard.ts`

```ts
import { Injectable, CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { UserService } from "../services/user.service";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector, private userService: UserService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>("roles", context.getHandler());
    const permissions = this.reflector.get<string[]>(
      "permissions",
      context.getHandler()
    );
    if (!roles && !permissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = await this.userService.findOne(request.user.id);

    if (roles) {
      const hasRole = () =>
        user.roles.some((role) => !!roles.find((item) => item === role.name));
      if (!hasRole()) {
        return false;
      }
    }

    if (permissions) {
      const hasPermission = () =>
        user.roles.some((role) =>
          role.permissions.some(
            (permission) =>
              !!permissions.find((item) => item === permission.name)
          )
        );
      if (!hasPermission()) {
        return false;
      }
    }

    return true;
  }
}
```

`src/decorators/roles.decorator.ts`

```ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
```

`src/decorators/permissions.decorator.ts`

```ts
import { SetMetadata } from "@nestjs/common";

export const Permissions = (...permissions: string[]) =>
  SetMetadata("permissions", permissions);
```

4. Create the entry file: `src/index.ts`

```ts
export * from "./entities/user.entity";
export * from "./entities/role.entity";
export * from "./entities/permission.entity";
export * from "./services/user.service";
export * from "./services/role.service";
export * from "./services/permission.service";
export * from "./guards/roles.guard";
export * from "./decorators/roles.decorator";
export * from "./decorators/permissions.decorator";
```

## Step 4: Build and Publish the Package

1. Build the package: Add a build script in `package.json`:

```json
"scripts": {
  "build": "tsc"
}
```

Run the build:

```bash
npm run build
```

2. Log in to npm:

```bash
npm login
```

3. Publish the package:

```bash
npm publish --access public
```

## Step 5: Use the Package in a NestJS Project

1. Install the package:

```bash
npm install nestjs-rbac
```

2. Use the package in your NestJS application:

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import {
  User,
  Role,
  Permission,
  UserService,
  RoleService,
  PermissionService,
  RolesGuard,
  Roles,
  Permissions,
} from "nestjs-rbac";

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: "postgres",
      host: process.env.DB_HOST,
      port: +process.env.DB_PORT,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [User, Role, Permission],
      synchronize: true,
    }),
    TypeOrmModule.forFeature([User, Role, Permission]),
  ],
  providers: [UserService, RoleService, PermissionService],
})
export class AppModule {}
```

# Create a plugin or configuration option for your package that allows users to specify custom entity names and additional fields for the User, Role, and Permission entities.

## Step 1: Create the RBAC Package

1. Set Up the Package Directory:

```bash
mkdir nestjs-rbac
cd nestjs-rbac
npm init -y
```

2. Install Dependencies:

```bash
npm install @nestjs/common @nestjs/core @nestjs/typeorm typeorm pg
```

3. Create the Directory Structure:

```bash
mkdir src
touch src/index.ts
mkdir -p src/entities src/services src/guards src/decorators src/interfaces
```

## Step 2: Implement the Package

1. Define Configuration Interface:

`src/interfaces/configuration.interface.ts:`

```ts
import { Type } from "@nestjs/common";
import { EntitySchema } from "typeorm";

export interface RbacOptions {
  userEntity: Type<any> | EntitySchema<any>;
  roleEntity: Type<any> | EntitySchema<any>;
  permissionEntity: Type<any> | EntitySchema<any>;
}
```

2. Create the RBAC Module:

`src/rbac.module.ts`:

```ts
import { DynamicModule, Module, Provider, Global } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { RbacOptions } from "./interfaces/configuration.interface";
import { UserService } from "./services/user.service";
import { RoleService } from "./services/role.service";
import { PermissionService } from "./services/permission.service";
import { RolesGuard } from "./guards/roles.guard";

@Global()
@Module({})
export class RbacModule {
  static forRoot(options: RbacOptions): DynamicModule {
    const providers: Provider[] = [
      UserService,
      RoleService,
      PermissionService,
      {
        provide: "USER_ENTITY",
        useValue: options.userEntity,
      },
      {
        provide: "ROLE_ENTITY",
        useValue: options.roleEntity,
      },
      {
        provide: "PERMISSION_ENTITY",
        useValue: options.permissionEntity,
      },
      RolesGuard,
    ];

    return {
      module: RbacModule,
      imports: [
        TypeOrmModule.forFeature([
          options.userEntity,
          options.roleEntity,
          options.permissionEntity,
        ]),
      ],
      providers: providers,
      exports: providers,
    };
  }
}
```

3. Create the Entities: `src/entities/user.entity.ts`

```ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToMany,
  JoinTable,
} from "typeorm";
import { Role } from "./role.entity";

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  password: string;

  @ManyToMany(() => Role)
  @JoinTable()
  roles: Role[];
}
```

`src/entities/role.entity.ts:`

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Permission } from "./permission.entity";
import { User } from "./user.entity";

@Entity()
export class Role {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Permission, (permission) => permission.roles)
  permissions: Permission[];

  @ManyToMany(() => User, (user) => user.roles)
  users: User[];
}
```

`src/entities/permission.entity.ts`

```ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from "typeorm";
import { Role } from "./role.entity";

@Entity()
export class Permission {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}
```

4. Create the Services:`src/services/user.service.ts`

```ts
import { Injectable, Inject } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";

@Injectable()
export class UserService {
  constructor(
    @Inject("USER_ENTITY") private readonly userEntity,
    @InjectRepository("USER_ENTITY")
    private readonly userRepository: Repository<any>
  ) {}

  findAll(): Promise<any[]> {
    return this.userRepository.find({
      relations: ["roles", "roles.permissions"],
    });
  }

  findOne(id: number): Promise<any> {
    return this.userRepository.findOne(id, {
      relations: ["roles", "roles.permissions"],
    });
  }

  // Additional methods for creating, updating, and deleting users
}
```

Similarly, create role.service.ts and permission.service.ts with the same structure, adjusting for the respective entities.

5. Create the Guards and Decorators: `src/guards/roles.guard.ts:`

```ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Inject,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { UserService } from "../services/user.service";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(UserService) private userService: UserService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>("roles", context.getHandler());
    const permissions = this.reflector.get<string[]>(
      "permissions",
      context.getHandler()
    );
    if (!roles && !permissions) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = await this.userService.findOne(request.user.id);

    if (roles) {
      const hasRole = () =>
        user.roles.some((role) => !!roles.find((item) => item === role.name));
      if (!hasRole()) {
        return false;
      }
    }

    if (permissions) {
      const hasPermission = () =>
        user.roles.some((role) =>
          role.permissions.some(
            (permission) =>
              !!permissions.find((item) => item === permission.name)
          )
        );
      if (!hasPermission()) {
        return false;
      }
    }

    return true;
  }
}
```

`src/decorators/roles.decorator.ts:`

```ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
```

`src/decorators/permissions.decorator.ts:`

```ts
import { SetMetadata } from "@nestjs/common";

export const Permissions = (...permissions: string[]) =>
  SetMetadata("permissions", permissions);
```

6. Create the Entry File: `src/index.ts:`

```ts
export * from "./entities/user.entity";
export * from "./entities/role.entity";
export * from "./entities/permission.entity";
export * from "./services/user.service";
export * from "./services/role.service";
export * from "./services/permission.service";
export * from "./guards/roles.guard";
export * from "./decorators/roles.decorator";
export * from "./decorators/permissions.decorator";
export * from "./rbac.module";
export * from "./interfaces/configuration.interface";
```

## Step 3: Build and Use the Package Locally

1. Build the Package:
   Add a build script in package.json:

```json
"scripts": {
  "build": "tsc"
}
```

Run the build:

```bash
npm run build
```

Link the Package Locally:

```bash
npm link
```

3. Use the Package in Your NestJS Project:

In your NestJS project, link the package:

```bash
npm link nestjs-rbac
```

4. Configure and Use the Package:

```ts
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { RbacModule, RbacOptions } from "nestjs-rbac";
import { ExtendedUser } from "./entities/extended-user.entity";
import { CustomRole } from "./entities/custom-role.entity";
import { CustomPermission } from "./entities/custom-permission.entity";

const rbacOptions: RbacOptions = {
  userEntity: ExtendedUser,
  roleEntity: CustomRole,
  permissionEntity: CustomPermission,
};

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: "postgres",
      host: process.env.DB_HOST,
      port: +process.env.DB_PORT,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [ExtendedUser, CustomRole, CustomPermission],
      synchronize: true,
    }),
    RbacModule.forRoot(rbacOptions),
  ],
})
export class AppModule {}
```

5. Extended User Entity:

`src/entities/extended-user.entity.ts`

```ts
import { Entity, Column } from "typeorm";
import { User } from "nestjs-rbac";

@Entity()
export class ExtendedUser extends User {
  @Column({ nullable: true })
  additionalField: string;
}
```

6. Custom Role and Permission Entities:

`src/entities/custom-role.entity.ts:`

```ts
import { Entity, Column } from "typeorm";
import { Role } from "nestjs-rbac";

@Entity()
export class CustomRole extends Role {
  @Column({ nullable: true })
  description: string;
}
```

`src/entities/custom-permission.entity.ts`

```ts
import { Entity, Column } from "typeorm";
import { Permission } from "nestjs-rbac";

@Entity()
export class CustomPermission extends Permission {
  @Column({ nullable: true })
  description: string;
}
```

# Upload this package to npm, follow these steps:

## Step 1: Prepare Your Package

1. Ensure your package is ready for distribution:

   - Make sure all necessary files are included (`src/` directory, `package.json`, `README.md`, etc.).
   - Verify that your package can be built successfully (`npm run build`).

2. Update `package.json`:

   - Ensure `name`, `version`, `description`, `author`, `license`, and other fields are correctly set.
   - Add any additional metadata or scripts that might be necessary.

3. Create a `README.md` file:

   - Provide documentation on how to install, configure, and use your package.
   - Include examples, API references, and any other relevant information.

## Step 2: Publish to npm

1. Login to npm:

   ```bash
   	npm login
   ```

   - Enter your npm username, password, and email when prompted.

2. Publish your package:

   ```bash
   npm publish --access public
   ```

   - This command publishes your package to the npm registry as a public package.

## Step 3: Maintain Your Package

1. Versioning:

   - Use semantic versioning (SemVer) for your package (major.minor.patch).
   - Update the version number in package.json before publishing a new version.

2. Documentation:

   - Keep your README.md updated with the latest information about the package.
   - Respond to issues and improve documentation based on user feedback.

3. Testing:

   - Ensure your package is well-tested before each release to maintain quality.

## Example package.json

Here's an example `package.json` snippet with relevant fields:

```json
{
  "name": "nestjs-rbac",
  "version": "1.0.0",
  "description": "Role-Based Access Control (RBAC) package for NestJS applications.",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "test": "jest"
  },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/yourusername/nestjs-rbac.git"
  },
  "keywords": ["nestjs", "rbac", "authorization", "role-based-access-control"],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "@nestjs/common": "^8.0.0",
    "@nestjs/core": "^8.0.0",
    "@nestjs/typeorm": "^8.0.0",
    "typeorm": "^0.2.0",
    "pg": "^8.0.0"
  },
  "devDependencies": {
    "@types/node": "^16.0.0",
    "@types/jest": "^27.0.0",
    "jest": "^27.0.0",
    "typescript": "^4.5.0"
  }
}
```
