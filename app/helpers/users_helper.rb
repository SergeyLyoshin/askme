module UsersHelper
  def user_avatar(user)
    if user.avatar_url.present?
        user.avatar_url
    else
        asset_path 'avatar.jpg'
    end
  end
    
    def inclination(count, one, few, many)
      return many if (11..14).include?(count % 100)
      return one if count % 10 == 1
      return few if (2..4).include?(count % 10)
    
      many
    end
end