Rails.application.routes.draw do
  get 'welcome/index'

  resources :users do
      resources :entries
  end

  root 'welcome#index'
end
