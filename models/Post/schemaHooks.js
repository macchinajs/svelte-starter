import bcrypt from 'bcryptjs'
import slugify from 'slugify'
import S3 from "aws-sdk/clients/s3"

const s3 = new S3();

const hooks = {
  pre: {
    save: function (next) {
      if (this.isModified('image')) {
        const params = {Bucket: "fpaboim-fabo", Key: this.image};
        const url = s3.getSignedUrl('getObject', params);
        console.log('The URL is', url);
        this.image = url
      }

      // only run this if we're messing with the password field, or else bcrypt
      // will on all saves!
      if (!this.isModified('title')) {
        return next()
      }

      this.slug = slugify(this.title)
      return next()
    }
  }
}

export default hooks
