import HTTP_STATUS from '../constants/httpStatus.js'
import { USERS_MESSAGES } from '../constants/messages.js'

export class ErrorWithStatus {
  message
  status
  constructor({ message, status }) {
    this.message = message
    this.status = status
  }
}

export class EntityError extends ErrorWithStatus {
  errors
  constructor({ message = USERS_MESSAGES.VALIDATION_ERROR, errors }) {
    super({ message, status: HTTP_STATUS.UNPROCESSABLE_ENTITY })
    this.errors = errors
  }
}
