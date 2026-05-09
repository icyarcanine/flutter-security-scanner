import 'package:flutter_bloc/flutter_bloc.dart';

class AuthState {
  final String? jwtToken;
  final String? refreshToken;
  final bool isAuthenticated;

  AuthState({this.jwtToken, this.refreshToken, this.isAuthenticated = false});
}

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  // Storing sensitive tokens in BLoC state
  AuthBloc() : super(AuthState()) {
    on<LoginEvent>((event, emit) {
      emit(AuthState(
        jwtToken: event.token,
        refreshToken: event.refreshToken,
        isAuthenticated: true,
      ));
    });
  }
}

abstract class AuthEvent {}

class LoginEvent extends AuthEvent {
  final String token;
  final String refreshToken;

  LoginEvent(this.token, this.refreshToken);
}
