<script>
  import {onMount} from 'svelte'
  import {post} from '$lib/req_utils'

  export const ssr = false
  export const prerender = false

  export let users = []
  onMount(async () => {
    users = await post('/user/find')
  })
</script>

<div class="overflow-x-auto">
  <table class="table w-full">
    <thead>
      <tr>
        <th>
          <label>
            <input type="checkbox" class="checkbox">
          </label>
        </th>
        <th>body</th>
        <th>created</th>
        <th>edited</th>
        <th>deleted</th>
        <th>author</th>
        <th>post</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <th>
          <label>
            <input type="checkbox" class="checkbox">
          </label>
        </th>
        <td>
          <div class="flex items-center space-x-3">
            <div class="avatar">
              <div class="w-12 h-12 mask mask-squircle">
                <img src="/tailwind-css-component-profile-13@56w.png" alt="Avatar Tailwind CSS Component">
              </div>
            </div>
            <div>
              <div class="font-bold">
                    Florida Garces
                  </div>
              <div class="text-sm opacity-50">
                    Poland
                  </div>
            </div>
          </div>
        </td>
        <td>
            Gaylord, Pacocha and Baumbach

          <br>
          <span class="badge badge-outline badge-sm">Web Developer IV</span>
        </td>
        <td>Purple</td>
        <th>
          <button class="btn btn-ghost btn-xs">details</button>
        </th>
      </tr>

    </tbody>

    <tfoot>
      <tr>
        <th></th>
        <th>body</th>
        <th>created</th>
        <th>edited</th>
        <th>deleted</th>
        <th>author</th>
        <th>post</th>
        <th></th>
      </tr>
    </tfoot>
  </table>
</div>
