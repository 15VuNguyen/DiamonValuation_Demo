export const wrapAsync = (func) => {
  return async (req, res, next) => {
    //tạo ra cấu trúc try catch
    try {
      await func(req, res, next)
    } catch (error) {
      next(error)
    }
  }
}
