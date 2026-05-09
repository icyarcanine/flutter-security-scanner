import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthState {
  final bool isAuthenticated;
  final String? userId;

  AuthState({this.isAuthenticated = false, this.userId});
}

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final _secureStorage = const FlutterSecureStorage();

  AuthBloc() : super(AuthState()) {
    on<LoginEvent>((event, emit) async {
      // Store tokens securely, keep only non-sensitive state
      await _secureStorage.write(key: 'jwt', value: event.token);
      await _secureStorage.write(key: 'refresh', value: event.refreshToken);
      emit(AuthState(isAuthenticated: true, userId: event.userId));
    });

    on<LogoutEvent>((event, emit) async {
      await _secureStorage.deleteAll();
      emit(AuthState());
    });
  }
}

abstract class AuthEvent {}

class LoginEvent extends AuthEvent {
  final String token;
  final String refreshToken;
  final String userId;

  LoginEvent(this.token, this.refreshToken, this.userId);
}

class LogoutEvent extends AuthEvent {}
