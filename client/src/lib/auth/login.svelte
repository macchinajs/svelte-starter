<script context="module">
  export const prerender = true
</script>

<script>
  import { goto } from "$app/navigation"
  import { User, modal } from '../../store/store'
  import { post, setLocalStorage } from '$lib/req_utils'
  import { getErrors } from '$lib/form_utils.js'
  import userValidators from '$macchina/models/User/validation.js'

  export let redirect = true
  export let showlogin

  let resetInput = () => {
    return {
      email:     '',
      password:  '',
    }
  }
  let formInput = resetInput()
  let errorMsgs = resetInput()

  const handleSubmit = async () => {
    try {
      let res = {}

      const validationErrors = getErrors(formInput, userValidators)
      errorMsgs = {...errorMsgs, ...validationErrors}

      for (let error in errorMsgs) {
        if (errorMsgs[error] != '')
          return
      }

      if (!res.errors) {
        res = await post('/user/auth/login', {
          email: formInput.email,
          password: formInput.password
        })
      }

      if (res.errors) {
        let errors = res.errors
        for (let error in errors) {
          errorMsgs[error] = errors[error].message
        }
        return
      }

      if (res.token) {
        setLocalStorage('jwt', res.token)
      }

      delete res.token
      const user = res
      User.set({
        ...$User,
        ...user
      })
      $modal = false

      if (redirect) {
        await goto('/')
      }
    } catch(err) {
      alert(err.error)
    }
  }
</script>

<div class="">
  <h1 class="text-2xl font-bold mb-8">Login</h1>
  <form id="form" on:submit|preventDefault={handleSubmit} novalidate on:keydown={() => errorMsgs = resetInput()}>

    <div class="z-0 w-full mb-5">
      <div class="flex flex-row items-center">
        <label for="email" class="text-right w-1/3 duration-300 pr-3 -z-1 origin-0 text-gray-500">Email</label>
        <input
          bind:value={formInput.email}
          type="email"
          name="email"
          placeholder=" "
          class="pt-3 pb-2 block w-full px-0 mt-0 bg-transparent border-0 border-b-2 appearance-none focus:outline-none focus:ring-0 focus:border-black border-gray-200"
        />
      </div>
      <span class="h-10 text-sm text-red-600 {errorMsgs['email'] != '' ? 'visible':'invisible'}" id="error">{errorMsgs['email']}</span>
    </div>

    <div class="z-0 w-full mb-5">
      <div class="flex flex-row items-center">
        <label for="password" class="text-right w-1/3 duration-300 pr-3 -z-1 origin-0 text-gray-500">Password</label>
        <input
          bind:value={formInput.password}
          type="password"
          name="password"
          placeholder=" "
          class="pt-3 pb-2 block w-full px-0 mt-0 bg-transparent border-0 border-b-2 appearance-none focus:outline-none focus:ring-0 focus:border-black border-gray-200"
        />
      </div>
      <span class="h-10 text-sm text-red-600 {errorMsgs['password'] != '' ? 'visible':'invisible'}" id="error">{errorMsgs['password']}</span>
    </div>

    <div class="pt-5 flex flex-col justify-center items-center">
      <button
        id="button"
        type="submit"
        class="w-full px-6 py-3 mt-3 text-lg text-white transition-all duration-150 ease-linear rounded-lg shadow outline-none bg-brand-500 hover:bg-brand-600 hover:shadow-lg focus:outline-none"
      >
        Login
      </button>

      <button
        id="login"
        type="button"
        on:click|preventDefault={() => showlogin=false}
        class="px-2 pt-4 pb-2 mt-3 text-lg text-brand-500 transition-all duration-150 ease-linear rounded-lg outline-none hover:text-brand-700"
      >
        Create Account
      </button>
    </div>

  </form>
</div>

<style style lang="postcss">

</style>
