//
// UserAPI.swift
//
// Generated by openapi-generator
// https://openapi-generator.tech
//

import Foundation
import Combine

open class UserAPI {
    /**
     Create user
     
     - parameter body: (body) Created user object 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func createUser(body: User, apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            createUserWithRequestBuilder(body: body).execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Create user
     - POST /user
     - This can only be done by the logged in user.
     - parameter body: (body) Created user object 
     - returns: RequestBuilder<Void> 
     */
    open class func createUserWithRequestBuilder(body: User) -> RequestBuilder<Void> {
        let path = "/user"
        let URLString = PetstoreClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: body)

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Creates list of users with given input array
     
     - parameter body: (body) List of user object 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func createUsersWithArrayInput(body: [User], apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            createUsersWithArrayInputWithRequestBuilder(body: body).execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Creates list of users with given input array
     - POST /user/createWithArray
     - parameter body: (body) List of user object 
     - returns: RequestBuilder<Void> 
     */
    open class func createUsersWithArrayInputWithRequestBuilder(body: [User]) -> RequestBuilder<Void> {
        let path = "/user/createWithArray"
        let URLString = PetstoreClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: body)

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Creates list of users with given input array
     
     - parameter body: (body) List of user object 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func createUsersWithListInput(body: [User], apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            createUsersWithListInputWithRequestBuilder(body: body).execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Creates list of users with given input array
     - POST /user/createWithList
     - parameter body: (body) List of user object 
     - returns: RequestBuilder<Void> 
     */
    open class func createUsersWithListInputWithRequestBuilder(body: [User]) -> RequestBuilder<Void> {
        let path = "/user/createWithList"
        let URLString = PetstoreClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: body)

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Delete user
     
     - parameter username: (path) The name that needs to be deleted 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func deleteUser(username: String, apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            deleteUserWithRequestBuilder(username: username).execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Delete user
     - DELETE /user/{username}
     - This can only be done by the logged in user.
     - parameter username: (path) The name that needs to be deleted 
     - returns: RequestBuilder<Void> 
     */
    open class func deleteUserWithRequestBuilder(username: String) -> RequestBuilder<Void> {
        var path = "/user/{username}"
        let usernamePreEscape = "\(APIHelper.mapValueToPathItem(username))"
        let usernamePostEscape = usernamePreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{username}", with: usernamePostEscape, options: .literal, range: nil)
        let URLString = PetstoreClientAPI.basePath + path
        let parameters: [String: Any]? = nil

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "DELETE", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Get user by user name
     
     - parameter username: (path) The name that needs to be fetched. Use user1 for testing. 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<User, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func getUserByName(username: String, apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<User, Error> {
        return Future<User, Error>.init { promise in
            getUserByNameWithRequestBuilder(username: username).execute(apiResponseQueue) { result -> Void in
                switch result {
                case let .success(response):
                    promise(.success(response.body!))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Get user by user name
     - GET /user/{username}
     - parameter username: (path) The name that needs to be fetched. Use user1 for testing. 
     - returns: RequestBuilder<User> 
     */
    open class func getUserByNameWithRequestBuilder(username: String) -> RequestBuilder<User> {
        var path = "/user/{username}"
        let usernamePreEscape = "\(APIHelper.mapValueToPathItem(username))"
        let usernamePostEscape = usernamePreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{username}", with: usernamePostEscape, options: .literal, range: nil)
        let URLString = PetstoreClientAPI.basePath + path
        let parameters: [String: Any]? = nil

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<User>.Type = PetstoreClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Logs user into the system
     
     - parameter username: (query) The user name for login 
     - parameter password: (query) The password for login in clear text 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<String, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func loginUser(username: String, password: String, apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<String, Error> {
        return Future<String, Error>.init { promise in
            loginUserWithRequestBuilder(username: username, password: password).execute(apiResponseQueue) { result -> Void in
                switch result {
                case let .success(response):
                    promise(.success(response.body!))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Logs user into the system
     - GET /user/login
     - responseHeaders: [X-Rate-Limit(Int), X-Expires-After(Date)]
     - parameter username: (query) The user name for login 
     - parameter password: (query) The password for login in clear text 
     - returns: RequestBuilder<String> 
     */
    open class func loginUserWithRequestBuilder(username: String, password: String) -> RequestBuilder<String> {
        let path = "/user/login"
        let URLString = PetstoreClientAPI.basePath + path
        let parameters: [String: Any]? = nil

        var url = URLComponents(string: URLString)
        url?.queryItems = APIHelper.mapValuesToQueryItems([
            "username": username.encodeToJSON(),
            "password": password.encodeToJSON(),
        ])

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<String>.Type = PetstoreClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Logs out current logged in user session
     
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func logoutUser(apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            logoutUserWithRequestBuilder().execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Logs out current logged in user session
     - GET /user/logout
     - returns: RequestBuilder<Void> 
     */
    open class func logoutUserWithRequestBuilder() -> RequestBuilder<Void> {
        let path = "/user/logout"
        let URLString = PetstoreClientAPI.basePath + path
        let parameters: [String: Any]? = nil

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

    /**
     Updated user
     
     - parameter username: (path) name that need to be deleted 
     - parameter body: (body) Updated user object 
     - parameter apiResponseQueue: The queue on which api response is dispatched.
     - returns: AnyPublisher<Void, Error>
     */
    @available(OSX 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    open class func updateUser(username: String, body: User, apiResponseQueue: DispatchQueue = PetstoreClientAPI.apiResponseQueue) -> AnyPublisher<Void, Error> {
        return Future<Void, Error>.init { promise in
            updateUserWithRequestBuilder(username: username, body: body).execute(apiResponseQueue) { result -> Void in
                switch result {
                case .success:
                    promise(.success(()))
                case let .failure(error):
                    promise(.failure(error))
                }
            }
        }.eraseToAnyPublisher()
    }

    /**
     Updated user
     - PUT /user/{username}
     - This can only be done by the logged in user.
     - parameter username: (path) name that need to be deleted 
     - parameter body: (body) Updated user object 
     - returns: RequestBuilder<Void> 
     */
    open class func updateUserWithRequestBuilder(username: String, body: User) -> RequestBuilder<Void> {
        var path = "/user/{username}"
        let usernamePreEscape = "\(APIHelper.mapValueToPathItem(username))"
        let usernamePostEscape = usernamePreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{username}", with: usernamePostEscape, options: .literal, range: nil)
        let URLString = PetstoreClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: body)

        let url = URLComponents(string: URLString)

        let nillableHeaders: [String: Any?] = [
            :
        ]

        let headerParameters = APIHelper.rejectNilHeaders(nillableHeaders)

        let requestBuilder: RequestBuilder<Void>.Type = PetstoreClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "PUT", URLString: (url?.string ?? URLString), parameters: parameters, headers: headerParameters)
    }

}
