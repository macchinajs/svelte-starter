import validate from 'mongoose-validator'

import '$lib/.fabo/shared/lib/extendValidators.js'

// Token validation schema
///////////////////////////////////////////////////////////////////////////////
export default {
  userId: {
    required: true,
    validations: [
      validate({
      validator: "required",
      message: "Id is required"
    })],
  },
  token: {
    required: true,
    validations: [
      validate({
      validator: "required",
      message: "Token is required"
    })],
  },
}



