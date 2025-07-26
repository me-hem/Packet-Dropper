# Problem Statement 3: Explain the code snippet

Explain what the following code is attempting to do? You can explain by:
1. Explaining how the highlighted constructs work?
2. Giving use-cases of what these constructs could be used for.
3. What is the significance of the for loop with 4 iterations?
4. What is the significance of make(chan func(), 10)?
5. Why is “HERE1” not getting printed?


<pre><code>package main
import "fmt"
func main() {
    <b>cnp := make(chan func(), 10)</b>
    <b>for i := 0; i < 4; i++ {</b>
        <b>go func() {</b>
            <b>for f := range cnp {</b>
                <b>f()</b>
            <b>}</b>
        <b>}()</b>
    <b>}</b>
    <b>cnp <- func() {</b>
        <b>fmt.Println("HERE1")</b>
    <b>}</b>
    fmt.Println("Hello")
}
</code></pre>


# Solution

1. The highlighted part creates a buffered channel that holds up to 10 functions, then the for loop creates 4 worker goroutines where each worker continuously receives functions from the channel and execute them parallely.
2. These kinds of constructs can be used for various applications where parallel processing is required for efficiency, for example, writing multiple batches of data from LevelDB mempool to the SSTables in parallel.
3. The loop creates four workers which can work in parallel, so the significance is that tasks can be completed with up to 4x speed (depending on the nature of the work and system resources).
4. The buffer size of 10 means the main goroutine can send 10 functions to the channel without waiting. This prevents blocking and allows smooth communication between the sender and workers.
5. The main goroutine exits immediately after sending the function and printing "Hello", which terminates the entire program before any worker goroutine can execute the queued function. This creates a race condition where the workers get killed before they can process the function from the channel. **We can avoid this race condition by adding wait for some time so that workers can finish their task**
