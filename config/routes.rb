Rails.application.routes.draw do
  get 'welcome/index'

  resources :entries

  root 'welcome#index'
end
