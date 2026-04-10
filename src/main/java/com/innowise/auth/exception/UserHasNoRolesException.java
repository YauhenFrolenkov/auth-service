package com.innowise.auth.exception;

public class UserHasNoRolesException extends RuntimeException {
  public UserHasNoRolesException(String message) {
        super(message);
  }
}
