import './style.css'
import './reportFilters.css'
import { mount } from 'svelte'
import Root from './Root.svelte'
import { setupDefaultReportVisibility } from './reportVisibility'

const target = document.getElementById('app')
if (!target) {
  throw new Error('App mount target was not found')
}

const app = mount(Root, { target })
setupDefaultReportVisibility(target)

export default app
