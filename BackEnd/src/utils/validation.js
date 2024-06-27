import { validationResult } from 'express-validator'
import { EntityError, ErrorWithStatus } from '../models/Errors.js'

export const validate = (validation) => {
  return async (req, res, next) => {
    // sequential processing, stops running validations chain if one fails.
    await validation.run(req)

    const errors = validationResult(req)
    if (errors.isEmpty()) {
      return next()
    }

    const errorObjects = errors.mapped()

    const entityError = new EntityError({ errors: {} })

    //xử lý errorObject
    for (const key in errorObjects) {
      const { msg } = errorObjects[key] //lấy msg của từng cái lỗi
      //nếu msg có dạng ErrorWithStatus và status !== 422 thì ném cho error handler
      if (msg instanceof ErrorWithStatus && msg.status !== 422) {
        return next(msg)
      }
      //lưu các lỗi 422 từ errorObject vào entityError
      entityError.errors[key] = msg
    }

    //ở đây xử lí lỗi luôn, ném người dùng luôn, chứ kh ném về error handler tổng
    next(entityError)
  }
}
