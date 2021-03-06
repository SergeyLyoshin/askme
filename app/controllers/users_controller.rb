class UsersController < ApplicationController
  def index
  # Создаём массив из двух болванок пользователей. Вызываем метод # User.new, который создает модель, не записывая её в базу.
  # У каждого юзера мы прописали id, чтобы сымитировать реальную
  # ситуацию – иначе не будет работать хелпер путей
  @users = [
    User.new(
      id: 1,
      name: 'Vadim',
      username: 'installero',
      avatar_url: 'https://secure.gravatar.com/avatar/' \
        '71269686e0f757ddb4f73614f43ae445?s=100'
    ),
    User.new(id: 2, name: 'Misha', username: 'aristofun')
  ]
  end

  def new
  end

  def edit
  end

  def show
    @user = User.new(
      name: 'Vadim',
      username: 'installero'
    )

    @questions = [
      Question.new(text: 'Как дела?', created_at: Date.parse('12.06.2022')),
      Question.new(text: 'В чем смысл жизни?', created_at: Date.parse('12.06.2022'))
    ]

    @questions_count = @questions.count
    @answered_questions = @user.questions.count(&:answer)
    @unanswered_questions = @questions_count - @answered_questions

    @new_question = Question.new
  end
end
