Rails.application.routes.draw do
  get 'welcome/index'

  resources :entries
  resources :users
  root 'welcome#index'
end
